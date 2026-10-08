package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func qaServer(t *testing.T) *Server {
	t.Helper()
	t.Setenv("KUBE_DEMENTOR_REPORTS_DIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	return NewServer("")
}

func qaRequest(t *testing.T, method, target string, body any) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	var reader *bytes.Reader
	if s, ok := body.(string); ok {
		reader = bytes.NewReader([]byte(s))
	} else if b, ok := body.([]byte); ok {
		reader = bytes.NewReader(b)
	} else if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, target, reader)
	r.Header.Set("Content-Type", "application/json")
	return httptest.NewRecorder(), r
}

func qaDecode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %q", rec.Body.String())
	}
	return out
}

func qaSeededReport() *scanner.ScanReport {
	return &scanner.ScanReport{
		Metadata: scanner.ScanMetadata{
			ScanID:      "seed",
			ClusterName: "fixture-cluster",
			Mode:        "exploit",
			StartedAt:   time.Now(),
			FinishedAt:  time.Now(),
		},
		Findings: []scanner.Finding{
			{ID: "f1", RuleID: "KH-WRK-001", Severity: scanner.SevCritical, Title: "=SUM(A1:A5)", Category: scanner.CatWorkload,
				Resource: scanner.Resource{Kind: "Pod", Namespace: "team", Name: "target"}, Evidence: "=cmd|'/c calc'!A0"},
			{ID: "f2", RuleID: "KH-SEC-002", Severity: scanner.SevHigh, Title: "long-lived token",
				Resource: scanner.Resource{Kind: "Secret", Namespace: "team", Name: "legacy"}},
		},
	}
}

func TestNewScanIDsAreUniqueWithinTheSameMillisecond(t *testing.T) {
	ids := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := newScanID()
		if ids[id] {
			t.Fatalf("duplicate scan id %s", id)
		}
		ids[id] = true
	}
	if !strings.HasPrefix(newScanID(), "kh-") {
		t.Fatal("scan id prefix changed")
	}
}

func blockedServer(t *testing.T) *Server {
	t.Helper()
	s := qaServer(t)
	s.running["kh-blocker"] = &runState{ID: "kh-blocker", Status: "running", Started: time.Now(), Request: newScanReq{Mode: "scan"}}
	return s
}

func TestNewScanRejectsMalformedAndWrongValues(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"empty body", "", "invalid request body"},
		{"broken json", `{"mode": exploit}`, "invalid request body"},
		{"json array", `[]`, "invalid request body"},
		{"unknown mode", `{"context":"c","mode":"autopwn"}`, "unknown mode"},
		{"wrong type for mode", `{"mode":123}`, "invalid request body"},
		{"unknown level", `{"context":"c","level":"yolo"}`, "unknown exploit level"},
		{"unknown profile", `{"context":"c","profile":"paranoid"}`, "unknown profile"},
		{"namespace with space", `{"context":"c","namespace":"my namespace"}`, "invalid namespace"},
		{"namespace with slash", `{"context":"c","namespace":"../etc"}`, "invalid namespace"},
		{"namespace uppercase", `{"context":"c","namespace":"Team"}`, "invalid namespace"},
		{"namespace emoji", `{"context":"c","namespace":"team🚀"}`, "invalid namespace"},
		{"exclusion malformed yaml", `{"context":"c","exclusionYaml":"rules: [ {"}`, "invalid exclusionYaml"},
		{"exclusion rule without ruleId", `{"context":"c","exclusionYaml":"rules:\n  - namespaces: [x]"}`, "invalid exclusionYaml"},
		{"exclusion zero rules", `{"context":"c","exclusionYaml":"version: 1\nrules: []"}`, "no rules"},
		{"exclusion bad regex", `{"context":"c","exclusionYaml":"rules:\n  - ruleIdPattern: \"[unclosed\""}`, "invalid exclusionYaml"},
		{"exclusion bad severityMin", `{"context":"c","exclusionYaml":"rules:\n  - ruleId: KH-WRK-001\n    severityMin: hig"}`, "invalid severityMin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := blockedServer(t)
			rec, r := qaRequest(t, "POST", "/api/scans", tc.body)
			s.handleNewScan(rec, r)
			if rec.Code != 400 {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("error %q does not mention %q", rec.Body.String(), tc.want)
			}
		})
	}
}

func TestNewScanAppliesDefaultsInsteadOfRejectingEmptyValues(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"json null body", `null`},
		{"empty mode falls back to exploit", `{"context":"c","mode":""}`},
		{"empty level falls back to read-only", `{"context":"c","level":""}`},
		{"blank exclusion yaml is ignored", `{"context":"c","exclusionYaml":"   \n  "}`},
		{"missing profile defaults to external", `{"context":"c"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := blockedServer(t)
			rec, r := qaRequest(t, "POST", "/api/scans", tc.body)
			s.handleNewScan(rec, r)
			if rec.Code != 409 {
				t.Fatalf("expected defaults to pass validation and hit the single-scan guard (409), got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNewScanAcceptsValidEdgeCaseValues(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"namespace max length", `{"context":"c","namespace":"` + strings.Repeat("a", 63) + `"}`},
		{"namespace single char", `{"context":"c","namespace":"x"}`},
		{"namespace underscore", `{"context":"c","namespace":"team_a"}`},
		{"profile internal", `{"context":"c","profile":"internal"}`},
		{"json exclusion list", `{"context":"c","exclusionYaml":"[{\"ruleId\":\"KH-WRK-001\"}]"}`},
		{"yaml flow style", `{"context":"c","exclusionYaml":"{rules: [{ruleId: KH-WRK-001}]}"}`},
		{"severityMin lowercase", `{"context":"c","exclusionYaml":"rules:\n  - ruleId: KH-WRK-001\n    severityMin: high"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := blockedServer(t)
			rec, r := qaRequest(t, "POST", "/api/scans", tc.body)
			s.handleNewScan(rec, r)
			if rec.Code != 409 {
				t.Fatalf("expected valid payload to pass validation and hit the single-scan guard (409), got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNewScanRejectsOversizedBody(t *testing.T) {
	s := qaServer(t)
	huge := `{"context":"c","exclusionYaml":"` + strings.Repeat("a", maxScanBodyBytes) + `"}`
	rec, r := qaRequest(t, "POST", "/api/scans", huge)
	s.handleNewScan(rec, r)
	if rec.Code != 413 {
		t.Fatalf("expected 413 for %d byte body, got %d", len(huge), rec.Code)
	}
}

func TestNewScanRefusesConcurrentRuns(t *testing.T) {
	s := qaServer(t)
	s.running["kh-live"] = &runState{ID: "kh-live", Status: "running", Started: time.Now().Add(-time.Minute), Request: newScanReq{Mode: "chain"}}
	rec, r := qaRequest(t, "POST", "/api/scans", map[string]string{"context": "c", "mode": "exploit"})
	s.handleNewScan(rec, r)
	if rec.Code != 409 {
		t.Fatalf("expected 409 while a scan is running, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "kh-live") {
		t.Fatalf("409 error should name the running scan: %s", rec.Body.String())
	}
}

func TestScanFailsCleanlyWithUnresolvableContext(t *testing.T) {
	s := qaServer(t)
	kubeconfig := filepath.Join(t.TempDir(), "empty-kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\ncontexts: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)
	rec, r := qaRequest(t, "POST", "/api/scans", map[string]string{"context": "definitely-missing-context", "mode": "scan", "namespace": "team"})
	s.handleNewScan(rec, r)
	if rec.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	status := ""
	var last map[string]any
	for time.Now().Before(deadline) {
		rec2, r2 := qaRequest(t, "GET", "/api/scans/"+body.ID, nil)
		r2.SetPathValue("id", body.ID)
		s.handleGetScan(rec2, r2)
		if rec2.Code == 200 {
			last = qaDecode(t, rec2)
			if st, _ := last["status"].(string); st != "running" {
				status = st
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status != "failed" {
		t.Fatalf("expected failed status, got %q (last response: %v)", status, last)
	}
	if errText, _ := last["error"].(string); errText == "" {
		t.Fatal("failed scan must carry an error message")
	}
	if !strings.Contains(last["error"].(string), "definitely-missing-context") {
		t.Fatalf("error should explain the context problem: %v", last["error"])
	}

	rec3, r3 := qaRequest(t, "GET", "/api/scans", nil)
	s.handleListScans(rec3, r3)
	var list []map[string]any
	if err := json.Unmarshal(rec3.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0]["status"] != "failed" {
		t.Fatalf("failed scans must remain visible in the scan list, got %s", rec3.Body.String())
	}
}

func TestGetAndListScansUnknownIDs(t *testing.T) {
	s := qaServer(t)
	rec, r := qaRequest(t, "GET", "/api/scans/does-not-exist", nil)
	r.SetPathValue("id", "does-not-exist")
	s.handleGetScan(rec, r)
	if rec.Code != 404 {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	rec, r = qaRequest(t, "GET", "/api/scans", nil)
	s.handleListScans(rec, r)
	if rec.Code != 200 {
		t.Fatalf("expected 200 list, got %d", rec.Code)
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list must be a JSON array, got %q", rec.Body.String())
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d entries", len(list))
	}
}

func TestListScansIncludesRunningScan(t *testing.T) {
	s := qaServer(t)
	st := &runState{ID: "kh-run", Status: "running", Started: time.Now(), Request: newScanReq{Mode: "chain"}}
	s.running["kh-run"] = st
	rec, r := qaRequest(t, "GET", "/api/scans", nil)
	s.handleListScans(rec, r)
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0]["id"] != "kh-run" || list[0]["status"] != "running" {
		t.Fatalf("unexpected list: %q", rec.Body.String())
	}
}

func TestSSEMultiLineLogPayloadsStayOnTheWire(t *testing.T) {
	rec := httptest.NewRecorder()
	sseSend(rec, "log", "line one\nline two\n\nline four")
	out := rec.Body.String()
	want := "event: log\ndata: line one\ndata: line two\ndata: \ndata: line four\n\n"
	if out != want {
		t.Fatalf("SSE payload wrong:\n got %q\nwant %q", out, want)
	}
}

func TestSSEUnknownScanReturns404AndCompletedScanEmitsDone(t *testing.T) {
	s := qaServer(t)
	rec, r := qaRequest(t, "GET", "/api/scans/none/events", nil)
	r.SetPathValue("id", "none")
	s.handleScanEvents(rec, r)
	if rec.Code != 404 {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	s.store.Save("done-scan", newScanReq{}, qaSeededReport())
	rec2, r2 := qaRequest(t, "GET", "/api/scans/done-scan/events", nil)
	r2.SetPathValue("id", "done-scan")
	s.handleScanEvents(rec2, r2)
	if rec2.Code != 200 || !strings.Contains(rec2.Body.String(), "event: done") {
		t.Fatalf("completed scan should emit done immediately: %d %q", rec2.Code, rec2.Body.String())
	}
}

func TestAcceptRejectsMalformedBodiesAndUnknownIDs(t *testing.T) {
	s := qaServer(t)
	s.store.Save("seed", newScanReq{}, qaSeededReport())

	for _, tc := range []struct {
		name   string
		target string
		body   string
		pathID string
		want   int
	}{
		{"broken body", "/api/scans/seed/accept", `{"findingId": oops}`, "seed", 400},
		{"empty body", "/api/scans/seed/accept", "", "seed", 400},
		{"unknown scan", "/api/scans/nope/accept", `{"findingId":"f1"}`, "nope", 404},
		{"unknown finding", "/api/scans/seed/accept", `{"findingId":"missing"}`, "seed", 404},
		{"empty finding id", "/api/scans/seed/accept", `{"findingId":""}`, "seed", 404},
		{"unaccept unknown scan", "/api/scans/nope/unaccept", `{"findingId":"f1"}`, "nope", 404},
		{"unaccept not accepted", "/api/scans/seed/unaccept", `{"findingId":"f1"}`, "seed", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, r := qaRequest(t, "POST", tc.target, tc.body)
			r.SetPathValue("id", tc.pathID)
			if strings.Contains(tc.target, "/accept") && !strings.Contains(tc.target, "/unaccept") {
				s.handleAccept(rec, r)
			} else {
				s.handleUnaccept(rec, r)
			}
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d: %s", tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAcceptUnacceptRoundtripKeepsSummaryConsistent(t *testing.T) {
	s := qaServer(t)
	rep := qaSeededReport()
	s.store.Save("seed", newScanReq{}, rep)

	rec, r := qaRequest(t, "POST", "/api/scans/seed/accept", map[string]any{"findingId": "f1", "reason": "expected", "by": "qa", "global": false})
	r.SetPathValue("id", "seed")
	s.handleAccept(rec, r)
	if rec.Code != 200 {
		t.Fatalf("accept failed: %d %s", rec.Code, rec.Body.String())
	}
	out := qaDecode(t, rec)
	if summary, ok := out["summary"].(map[string]any); !ok || int(summary["total"].(float64)) != 1 {
		t.Fatalf("summary should show 1 active finding: %v", out["summary"])
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "f2" {
		t.Fatalf("f1 should leave the active list, got %v", rep.Findings)
	}
	if len(rep.AcceptedFindings) != 1 || rep.AcceptedFindings[0].AcceptedBy != "qa" {
		t.Fatalf("f1 should be accepted by qa: %v", rep.AcceptedFindings)
	}

	rec, r = qaRequest(t, "POST", "/api/scans/seed/accept", map[string]any{"findingId": "f1"})
	r.SetPathValue("id", "seed")
	s.handleAccept(rec, r)
	if rec.Code != 404 {
		t.Fatalf("double accept must 404, got %d", rec.Code)
	}

	rec, r = qaRequest(t, "POST", "/api/scans/seed/unaccept", map[string]any{"findingId": "f1"})
	r.SetPathValue("id", "seed")
	s.handleUnaccept(rec, r)
	if rec.Code != 200 {
		t.Fatalf("unaccept failed: %d %s", rec.Code, rec.Body.String())
	}
	if len(rep.Findings) != 2 || len(rep.AcceptedFindings) != 0 {
		t.Fatalf("unaccept should restore 2 active findings: %d active %d accepted", len(rep.Findings), len(rep.AcceptedFindings))
	}
	if rep.Findings[0].Accepted || rep.Findings[0].AcceptedScope != "" {
		t.Fatalf("unaccepted finding must lose its accepted state: %+v", rep.Findings[0])
	}
}

func TestGlobalAcceptLifecycleAndCorruptFileProtection(t *testing.T) {
	s := qaServer(t)

	rec, r := qaRequest(t, "POST", "/api/accepted", `not json`)
	s.handleGlobalAccept(rec, r)
	if rec.Code != 400 {
		t.Fatalf("bad body must 400, got %d", rec.Code)
	}
	rec, r = qaRequest(t, "POST", "/api/accepted", map[string]any{"ruleId": "KH-WRK-001"})
	s.handleGlobalAccept(rec, r)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "signature required") {
		t.Fatalf("missing signature must 400, got %d %s", rec.Code, rec.Body.String())
	}

	rec, r = qaRequest(t, "POST", "/api/accepted", map[string]any{"signature": "sig-1", "ruleId": "KH-WRK-001", "title": "privileged pod"})
	s.handleGlobalAccept(rec, r)
	if rec.Code != 200 {
		t.Fatalf("add failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, r = qaRequest(t, "GET", "/api/accepted", nil)
	s.handleGlobalAcceptedList(rec, r)
	out := qaDecode(t, rec)
	items := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 global accept, got %v", items)
	}

	rec, r = qaRequest(t, "DELETE", "/api/accepted/sig-1", nil)
	r.SetPathValue("sig", "sig-1")
	s.handleGlobalUnaccept(rec, r)
	if rec.Code != 200 {
		t.Fatalf("remove failed: %d %s", rec.Code, rec.Body.String())
	}

	corrupt := "this is not json {"
	home := os.Getenv("HOME")
	if err := os.MkdirAll(filepath.Join(home, ".kube-dementor"), 0o700); err != nil {
		t.Fatal(err)
	}
	acceptedPath := filepath.Join(home, ".kube-dementor", "accepted.json")
	if err := os.WriteFile(acceptedPath, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, r = qaRequest(t, "POST", "/api/accepted", map[string]any{"signature": "sig-2", "ruleId": "KH-X"})
	s.handleGlobalAccept(rec, r)
	if rec.Code != 500 {
		t.Fatalf("corrupt accepted.json must surface an error, got %d %s", rec.Code, rec.Body.String())
	}
	data, err := os.ReadFile(acceptedPath)
	if err != nil || string(data) != corrupt {
		t.Fatalf("corrupt accepted.json must not be overwritten, got %q err=%v", string(data), err)
	}
}

func TestExclusionUploadMatrix(t *testing.T) {
	s := qaServer(t)
	s.store.Save("seed", newScanReq{}, qaSeededReport())

	cases := []struct {
		name string
		body string
		want int
	}{
		{"malformed yaml", "rules: [\n  - {ruleId:", 400},
		{"empty upload", "", 400},
		{"whitespace only", "   \n\n  ", 400},
		{"zero rules", "version: 1\nrules: []", 400},
		{"rule without ruleId", "rules:\n  - namespaces: [team]", 400},
		{"bad regex", "rules:\n  - ruleIdPattern: '*('", 400},
		{"bad severityMin", "rules:\n  - ruleId: KH-WRK-001\n    severityMin: urgent", 400},
		{"valid yaml", "rules:\n  - ruleId: KH-WRK-001\n    reason: expected", 200},
		{"valid json list", `[{"ruleId":"KH-WRK-001","reason":"expected"}]`, 200},
		{"yaml flow style", "{rules: [{ruleId: KH-WRK-001}]}", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sFresh := qaServer(t)
			sFresh.store.Save("seed", newScanReq{}, qaSeededReport())
			rec, r := qaRequest(t, "POST", "/api/scans/seed/exclusions", tc.body)
			r.SetPathValue("id", "seed")
			sFresh.handleUploadExclusions(rec, r)
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d: %s", tc.want, rec.Code, rec.Body.String())
			}
			if tc.want == 200 {
				out := qaDecode(t, rec)
				if out["newlyAccepted"].(float64) != 1 {
					t.Fatalf("expected 1 suppressed finding: %v", out)
				}
			}
		})
	}

	rec, r := qaRequest(t, "POST", "/api/scans/unknown/exclusions", "rules: []")
	r.SetPathValue("id", "unknown")
	s.handleUploadExclusions(rec, r)
	if rec.Code != 404 {
		t.Fatalf("unknown scan must 404, got %d", rec.Code)
	}

	big := bytes.Repeat([]byte("a"), maxExclusionBytes+1)
	rec, r = qaRequest(t, "POST", "/api/scans/seed/exclusions", big)
	r.SetPathValue("id", "seed")
	s.handleUploadExclusions(rec, r)
	if rec.Code != 413 {
		t.Fatalf("oversized exclusion upload must 413, got %d", rec.Code)
	}
}

func TestExclusionDownloadRoundtrip(t *testing.T) {
	s := qaServer(t)
	s.store.Save("seed", newScanReq{}, qaSeededReport())

	rec, r := qaRequest(t, "GET", "/api/scans/seed/exclusions", nil)
	r.SetPathValue("id", "seed")
	s.handleGetExclusions(rec, r)
	if rec.Code != 404 {
		t.Fatalf("no stored exclusions must 404, got %d", rec.Code)
	}

	rec, r = qaRequest(t, "POST", "/api/scans/seed/exclusions", "rules:\n  - ruleId: KH-SEC-002\n    reason: legacy token")
	r.SetPathValue("id", "seed")
	s.handleUploadExclusions(rec, r)
	if rec.Code != 200 {
		t.Fatalf("upload failed: %d %s", rec.Code, rec.Body.String())
	}

	rec, r = qaRequest(t, "GET", "/api/scans/seed/exclusions", nil)
	r.SetPathValue("id", "seed")
	s.handleGetExclusions(rec, r)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "KH-SEC-002") {
		t.Fatalf("stored exclusions must be downloadable: %d %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Fatalf("unexpected content type %q", ct)
	}
}

func TestCSVExportIncludesAcceptedFindingsAndNeutralizesFormulas(t *testing.T) {
	s := qaServer(t)
	rep := qaSeededReport()
	rep.AcceptedFindings = []scanner.Finding{{
		ID: "f3", RuleID: "KH-ACC-003", Severity: scanner.SevLow, Title: "@import url(evil)",
		Resource:        scanner.Resource{Kind: "ConfigMap", Namespace: "team", Name: "cfg"},
		Accepted:        true, AcceptedBy: "qa", AcceptedReason: "known", AcceptedScope: "scan",
	}}
	s.store.Save("seed", newScanReq{}, rep)

	rec, r := qaRequest(t, "GET", "/api/scans/seed/csv", nil)
	r.SetPathValue("id", "seed")
	s.handleCSV(rec, r)
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("csv failed: %d %s", rec.Code, body)
	}
	if strings.Contains(body, ",=SUM") || strings.Contains(body, ",=cmd") || strings.Contains(body, ",@import") {
		t.Fatalf("formula-like cells must be neutralized, got:\n%s", body)
	}
	if !strings.Contains(body, "'=SUM(A1:A5)") {
		t.Fatal("neutralized formula should keep readable text")
	}
	if !strings.Contains(body, "KH-ACC-003") || !strings.Contains(body, "known") {
		t.Fatalf("accepted findings must appear in the CSV:\n%s", body)
	}
	if !strings.Contains(body, "f1,") {
		t.Fatal("active findings must still be exported")
	}

	rec, r = qaRequest(t, "GET", "/api/scans/unknown/csv", nil)
	r.SetPathValue("id", "unknown")
	s.handleCSV(rec, r)
	if rec.Code != 404 {
		t.Fatalf("unknown scan csv must 404, got %d", rec.Code)
	}
}

func TestLiveExploitGuards(t *testing.T) {
	s := qaServer(t)
	rep := qaSeededReport()
	s.store.Save("seed", newScanReq{}, rep)

	rec, r := qaRequest(t, "GET", "/api/scans/seed/findings/f1/capabilities", nil)
	r.SetPathValue("id", "seed")
	r.SetPathValue("fid", "f1")
	s.handleCapabilities(rec, r)
	out := qaDecode(t, rec)
	if rec.Code != 200 {
		t.Fatalf("capabilities listing failed: %d %s", rec.Code, rec.Body.String())
	}
	if caps, ok := out["capabilities"].([]any); !ok || len(caps) != 0 {
		t.Fatalf("finding without live exploit data must expose no capabilities: %v", out["capabilities"])
	}

	rec, r = qaRequest(t, "GET", "/api/scans/seed/findings/unknown/capabilities", nil)
	r.SetPathValue("id", "seed")
	r.SetPathValue("fid", "unknown")
	s.handleCapabilities(rec, r)
	if rec.Code != 404 {
		t.Fatalf("unknown finding must 404, got %d", rec.Code)
	}

	s.AllowLiveExploit = true
	rec, r = qaRequest(t, "POST", "/api/scans/seed/findings/f1/exploit", map[string]any{"capability": "pod-shell", "confirmText": "wrong"})
	r.SetPathValue("id", "seed")
	r.SetPathValue("fid", "f1")
	s.handleLiveExploit(rec, r)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "confirmation mismatch") {
		t.Fatalf("wrong confirm text must 400, got %d %s", rec.Code, rec.Body.String())
	}

	rec, r = qaRequest(t, "POST", "/api/scans/seed/findings/f1/exploit", map[string]any{"capability": "does-not-exist", "confirmText": "fixture-cluster"})
	r.SetPathValue("id", "seed")
	r.SetPathValue("fid", "f1")
	s.handleLiveExploit(rec, r)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "not available") {
		t.Fatalf("unknown capability must 400, got %d %s", rec.Code, rec.Body.String())
	}

	rec, r = qaRequest(t, "POST", "/api/scans/seed/findings/unknown/exploit", map[string]any{"capability": "pod-shell", "confirmText": "fixture-cluster"})
	r.SetPathValue("id", "seed")
	r.SetPathValue("fid", "unknown")
	s.handleLiveExploit(rec, r)
	if rec.Code != 404 {
		t.Fatalf("unknown finding must 404, got %d", rec.Code)
	}

	s.AllowLiveExploit = false
	rec, r = qaRequest(t, "POST", "/api/scans/seed/findings/f1/exploit", map[string]any{"capability": "pod-shell", "confirmText": "fixture-cluster"})
	r.SetPathValue("id", "seed")
	r.SetPathValue("fid", "f1")
	s.handleLiveExploit(rec, r)
	if rec.Code != 403 {
		t.Fatalf("live exploit disabled must 403, got %d", rec.Code)
	}

	rec, r = qaRequest(t, "GET", "/api/scans/seed/findings/f1/shell-status?confirm=fixture-cluster", nil)
	r.SetPathValue("id", "seed")
	r.SetPathValue("fid", "f1")
	s.handleShellStatus(rec, r)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "disabled") {
		t.Fatalf("shell status must reject when live exploit is off: %d %s", rec.Code, rec.Body.String())
	}
}

func TestChainEndpointsRejectUnknownScans(t *testing.T) {
	s := qaServer(t)
	rec, r := qaRequest(t, "POST", "/api/scans/unknown/chain/cleanup", nil)
	r.SetPathValue("id", "unknown")
	s.handleChainCleanup(rec, r)
	if rec.Code != 404 {
		t.Fatalf("cleanup for unknown scan must 404, got %d", rec.Code)
	}
	rec, r = qaRequest(t, "GET", "/api/scans/unknown/chain/pods", nil)
	r.SetPathValue("id", "unknown")
	s.handleChainPods(rec, r)
	if rec.Code != 404 {
		t.Fatalf("chain pods for unknown scan must 404, got %d", rec.Code)
	}

	rep := qaSeededReport()
	rep.Findings = append(rep.Findings, scanner.Finding{
		ID: "chain-shell", RuleID: "KH-CHAIN-SHELL", Title: "verified exec",
		Resource: scanner.Resource{Kind: "Pod", Namespace: "tenant-a", Name: "escaped"},
	})
	s.store.Save("seed", newScanReq{}, rep)
	rec, r = qaRequest(t, "GET", "/api/scans/seed/chain/pods", nil)
	r.SetPathValue("id", "seed")
	s.handleChainPods(rec, r)
	out := qaDecode(t, rec)
	pods := out["pods"].([]any)
	if len(pods) != 1 {
		t.Fatalf("expected 1 chain shell pod, got %v", pods)
	}
}

func TestReportsSurviveRestartViaDisk(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KUBE_DEMENTOR_REPORTS_DIR", dir)
	t.Setenv("HOME", t.TempDir())

	s := NewServer("")
	rep := qaSeededReport()
	req := newScanReq{Context: "demo", Mode: "exploit", Namespace: "team"}
	s.store.Save("seed-scan", req, rep)
	s.persistReport("seed-scan", req, rep)

	restored := NewServer("")
	got, ok := restored.store.Get("seed-scan")
	if !ok {
		t.Fatal("report must survive a restart")
	}
	if len(got.Findings) != 2 || got.Metadata.ClusterName != "fixture-cluster" {
		t.Fatalf("restored report is wrong: %+v", got.Metadata)
	}
	storedReq, ok := restored.store.GetRequest("seed-scan")
	if !ok || storedReq.Context != "demo" {
		t.Fatalf("request must survive a restart: %+v", storedReq)
	}

	restored2 := NewServer("")
	if len(restored2.store.GetExclusion("seed-scan")) != 0 {
		t.Fatal("no exclusions uploaded, none should load")
	}
}

func TestPersistedCorruptFilesAreSkippedWithoutCrash(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KUBE_DEMENTOR_REPORTS_DIR", dir)
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wrongformat.json"), []byte(`{"format": 99, "id": "x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewServer("")
	if _, ok := s.store.Get("broken"); ok {
		t.Fatal("corrupt report must not load")
	}
	if _, ok := s.store.Get("x"); ok {
		t.Fatal("wrong-format report must not load")
	}
}

func TestExclusionsPersistAlongsideReport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KUBE_DEMENTOR_REPORTS_DIR", dir)
	t.Setenv("HOME", t.TempDir())

	s := NewServer("")
	req := newScanReq{Context: "demo"}
	s.store.Save("seed", req, qaSeededReport())
	s.store.SaveExclusion("seed", []byte("rules:\n  - ruleId: KH-WRK-001\n"))

	rec, r := qaRequest(t, "POST", "/api/scans/seed/exclusions", "rules:\n  - ruleId: KH-SEC-002\n    reason: legacy")
	r.SetPathValue("id", "seed")
	s.handleUploadExclusions(rec, r)
	if rec.Code != 200 {
		t.Fatalf("upload failed: %d %s", rec.Code, rec.Body.String())
	}

	restored := NewServer("")
	if excl := restored.store.GetExclusion("seed"); !strings.Contains(string(excl), "KH-SEC-002") {
		t.Fatalf("uploaded exclusions must persist: %q", string(excl))
	}
}

func TestAcceptanceStatePersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KUBE_DEMENTOR_REPORTS_DIR", dir)
	t.Setenv("HOME", t.TempDir())

	s := NewServer("")
	s.store.Save("seed", newScanReq{}, qaSeededReport())
	rec, r := qaRequest(t, "POST", "/api/scans/seed/accept", map[string]any{"findingId": "f1", "reason": "expected"})
	r.SetPathValue("id", "seed")
	s.handleAccept(rec, r)
	if rec.Code != 200 {
		t.Fatalf("accept failed: %d %s", rec.Code, rec.Body.String())
	}

	restored := NewServer("")
	got, _ := restored.store.Get("seed")
	if len(got.AcceptedFindings) != 1 {
		t.Fatalf("accepted state must survive restart, got %d accepted", len(got.AcceptedFindings))
	}
}

func TestConcurrentReportReadsAndAcceptsAreRaceFree(t *testing.T) {
	s := qaServer(t)
	s.store.Save("seed", newScanReq{}, qaSeededReport())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, r := qaRequest(t, "GET", "/api/scans/seed", nil)
			r.SetPathValue("id", "seed")
			s.handleGetScan(rec, r)
			if rec.Code != 200 {
				t.Errorf("read failed: %d", rec.Code)
			}
		}()
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			findingID := "f1"
			if i%2 == 1 {
				findingID = "f2"
			}
			rec, r := qaRequest(t, "POST", "/api/scans/seed/accept", map[string]any{"findingId": findingID})
			r.SetPathValue("id", "seed")
			s.handleAccept(rec, r)
			if rec.Code != 200 && rec.Code != 404 {
				t.Errorf("accept returned %d: %s", rec.Code, rec.Body.String())
			}
		}(i)
	}
	wg.Wait()
	rep, _ := s.store.Get("seed")
	if len(rep.Findings)+len(rep.AcceptedFindings) != 2 {
		t.Fatalf("findings must never be duplicated or lost: %d active + %d accepted", len(rep.Findings), len(rep.AcceptedFindings))
	}
}

func TestFilterHelpersHandleWrongSeverityStrings(t *testing.T) {
	fs := []scanner.Finding{
		{ID: "a", Severity: scanner.SevCritical},
		{ID: "b", Severity: scanner.SevInfo},
	}
	if got := filterBySeverity(fs, "bogus"); len(got) != 2 {
		t.Fatalf("unknown severity floor must keep everything, got %d", len(got))
	}
	if got := filterBySeverity(fs, "critical"); len(got) != 1 {
		t.Fatalf("lowercase severity must work, got %d", len(got))
	}
	if got := filterBySeverity(fs, "INFO"); len(got) != 2 {
		t.Fatalf("info floor keeps all, got %d", len(got))
	}
}

func TestConfigEndpointReflectsServerFlags(t *testing.T) {
	s := qaServer(t)
	rec, r := qaRequest(t, "GET", "/api/config", nil)
	s.handleConfig(rec, r)
	out := qaDecode(t, rec)
	if out["allowLiveExploit"] != false {
		t.Fatalf("default config wrong: %v", out)
	}
}
