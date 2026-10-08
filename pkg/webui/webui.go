package webui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/kube-dementor/kube-dementor/pkg/chainexploit"
	"github.com/kube-dementor/kube-dementor/pkg/exploiter"
	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/liveexploit"
	"github.com/kube-dementor/kube-dementor/pkg/podexec"
	"github.com/kube-dementor/kube-dementor/pkg/policy"
	"github.com/kube-dementor/kube-dementor/pkg/runner"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

const (
	maxScanBodyBytes      = 10 << 20
	maxExclusionBytes     = 10 << 20
	maxAcceptBodyBytes    = 1 << 20
)

var validScanModes = map[string]bool{
	"discover": true, "scan": true, "exploit": true, "chain": true,
}

var validScanLevels = map[string]bool{
	"safe": true, "read-only": true, "intrusive": true,
}

var validScanProfiles = map[string]bool{
	"external": true, "internal": true,
}

var namespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9_]{0,61}[a-z0-9])?$`)

var scanIDCounter atomic.Int64

func newScanID() string {
	return fmt.Sprintf("kh-%d-%d", time.Now().UnixMilli(), scanIDCounter.Add(1))
}

//go:embed assets/*
var assetsFS embed.FS

type Server struct {
	addr    string
	store   *Store
	running map[string]*runState
	mu      sync.Mutex
	repMu   sync.RWMutex

	AllowLiveExploit      bool
	AllowSidecarInjection bool

	guards map[string]*kubectx.ReadOnlyGuard

	sessions map[string]*kubectx.Session

	chainEngines map[string]*chainexploit.Engine
}

func NewServer(addr string) *Server {
	s := &Server{
		addr:         addr,
		store:        NewStore(),
		running:      make(map[string]*runState),
		guards:       make(map[string]*kubectx.ReadOnlyGuard),
		sessions:     make(map[string]*kubectx.Session),
		chainEngines: make(map[string]*chainexploit.Engine),
	}
	s.loadPersistedReports()
	return s
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/contexts", s.handleContexts)
	mux.HandleFunc("GET /api/scans", s.handleListScans)
	mux.HandleFunc("POST /api/scans", s.handleNewScan)
	mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	mux.HandleFunc("GET /api/scans/{id}/events", s.handleScanEvents)
	mux.HandleFunc("GET /api/config", s.handleConfig)
	mux.HandleFunc("GET /api/scans/{id}/findings/{fid}/capabilities", s.handleCapabilities)
	mux.HandleFunc("POST /api/scans/{id}/findings/{fid}/exploit", s.handleLiveExploit)
	mux.HandleFunc("GET /ws/scans/{id}/findings/{fid}/shell", s.handleShell)
	mux.HandleFunc("GET /api/scans/{id}/findings/{fid}/shell-status", s.handleShellStatus)
	mux.HandleFunc("GET /api/scans/{id}/csv", s.handleCSV)
	mux.HandleFunc("POST /api/scans/{id}/accept", s.handleAccept)
	mux.HandleFunc("POST /api/scans/{id}/unaccept", s.handleUnaccept)
	mux.HandleFunc("GET /api/accepted", s.handleGlobalAcceptedList)
	mux.HandleFunc("POST /api/accepted", s.handleGlobalAccept)
	mux.HandleFunc("DELETE /api/accepted/{sig}", s.handleGlobalUnaccept)
	mux.HandleFunc("POST /api/scans/{id}/exclusions", s.handleUploadExclusions)
	mux.HandleFunc("GET /api/scans/{id}/exclusions", s.handleGetExclusions)
	mux.HandleFunc("POST /api/scans/{id}/chain/cleanup", s.handleChainCleanup)
	mux.HandleFunc("GET /api/scans/{id}/chain/pods", s.handleChainPods)

	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	srv := &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("[webui] listening on http://%s", strings.TrimPrefix(s.addr, ":"))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleContexts(w http.ResponseWriter, r *http.Request) {
	kubeconfig := r.URL.Query().Get("kubeconfig")
	names, current, err := kubectx.ListContexts(kubeconfig)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"contexts": names,
		"current":  current,
	})
}

type newScanReq struct {
	Context            string `json:"context"`
	Kubeconfig         string `json:"kubeconfig"`
	Namespace          string `json:"namespace"`
	Mode               string `json:"mode"`
	Level              string `json:"level"`
	MinSeverity        string `json:"minSeverity"`
	HideFP             bool   `json:"hideFalsePositives"`
	EnableTrivy        bool   `json:"enableTrivy"`
	EnableNuclei       bool   `json:"enableNuclei"`
	DisableSafetyGuard bool   `json:"disableSafetyGuard"`

	EnableStealth       bool `json:"enableStealth"`
	EnableRuntimeExtras bool `json:"enableRuntimeExtras"`
	EnableCNIExtras     bool `json:"enableCNIExtras"`

	ExclusionYAML string `json:"exclusionYaml,omitempty"`

	RefreshThreatIntel bool `json:"refreshThreatIntel"`

	Profile string `json:"profile,omitempty"`
}

func (s *Server) handleNewScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxScanBodyBytes)
	var req newScanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBodyError(w, err, maxScanBodyBytes)
		return
	}
	if req.Mode == "" {
		req.Mode = "exploit"
	}
	if req.Level == "" {
		req.Level = "read-only"
	}
	if !validScanModes[req.Mode] {
		writeError(w, 400, fmt.Errorf("unknown mode %q (use discover, scan, exploit or chain)", req.Mode))
		return
	}
	if !validScanLevels[req.Level] {
		writeError(w, 400, fmt.Errorf("unknown exploit level %q (use safe, read-only or intrusive)", req.Level))
		return
	}
	if req.Profile != "" && !validScanProfiles[req.Profile] {
		writeError(w, 400, fmt.Errorf("unknown profile %q (use external or internal)", req.Profile))
		return
	}
	req.Namespace = strings.TrimSpace(req.Namespace)
	if req.Namespace != "" && !namespacePattern.MatchString(req.Namespace) {
		writeError(w, 400, fmt.Errorf("invalid namespace %q: must be a valid DNS-1123 name (lowercase alphanumerics, '-' or '_')", req.Namespace))
		return
	}
	if strings.TrimSpace(req.ExclusionYAML) != "" {
		if _, err := policy.ParseExclusions([]byte(req.ExclusionYAML)); err != nil {
			writeError(w, 400, fmt.Errorf("invalid exclusionYaml: %v", err))
			return
		}
		if req.Mode == "chain" {
			log.Printf("[webui] exclusions are validated but not applied in chain mode")
		}
	}

	s.mu.Lock()
	for _, other := range s.running {
		other.mu.Lock()
		stillRunning := other.Status == "running"
		errLine := fmt.Sprintf("a scan is already running (id %s, started %s, mode %s); wait for it to finish or open it from History",
			other.ID, other.Started.Format("15:04:05"), other.Request.Mode)
		other.mu.Unlock()
		if stillRunning {
			s.mu.Unlock()
			writeError(w, 409, fmt.Errorf("%s", errLine))
			return
		}
	}
	id := newScanID()
	st := &runState{
		ID:      id,
		Status:  "running",
		Request: req,
		Started: time.Now(),
	}
	s.running[id] = st
	s.mu.Unlock()

	go s.executeScan(st)

	writeJSON(w, 202, map[string]string{"id": id, "status": "running"})
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	all := s.store.List()
	s.mu.Lock()
	for _, st := range s.running {
		st.mu.Lock()
		status := st.Status
		started := st.Started
		request := st.Request
		st.mu.Unlock()
		all = append([]scanListEntry{{
			ID:      st.ID,
			Status:  status,
			Started: started,
			Request: request,
		}}, all...)
	}
	s.mu.Unlock()
	writeJSON(w, 200, all)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.repMu.RLock()
	rep, ok := s.store.Get(id)
	if ok {
		writeJSON(w, 200, map[string]any{
			"status": "completed",
			"report": rep,
		})
		s.repMu.RUnlock()
		return
	}
	s.repMu.RUnlock()
	s.mu.Lock()
	st, ok := s.running[id]
	s.mu.Unlock()
	if !ok {
		writeError(w, 404, fmt.Errorf("scan %s not found", id))
		return
	}
	st.mu.Lock()
	status, started, request, errMsg := st.Status, st.Started, st.Request, st.Err
	st.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"status":  status,
		"started": started,
		"request": request,
		"error":   errMsg,
	})
}

func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	st, ok := s.running[id]
	s.mu.Unlock()
	if !ok {

		if _, ok2 := s.store.Get(id); ok2 {
			setSSEHeaders(w)
			sseSend(w, "done", map[string]any{"status": "completed"})
			return
		}
		writeError(w, 404, fmt.Errorf("scan %s not found", id))
		return
	}

	setSSEHeaders(w)
	flusher, _ := w.(http.Flusher)

	idx := 0
	for {
		st.mu.Lock()
		newLines := append([]string(nil), st.logs[idx:]...)
		idx = len(st.logs)
		status := st.Status
		errMsg := st.Err
		st.mu.Unlock()

		for _, line := range newLines {
			sseSend(w, "log", line)
		}
		if flusher != nil {
			flusher.Flush()
		}

		if status != "running" {
			sseSend(w, "done", map[string]any{"status": status, "error": errMsg})
			if flusher != nil {
				flusher.Flush()
			}
			return
		}

		select {
		case <-r.Context().Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

type runState struct {
	ID      string
	Status  string
	Started time.Time
	Request newScanReq
	Err     string
	Report  *scanner.ScanReport

	mu   sync.Mutex
	logs []string
}

func (st *runState) log(s string) {
	st.mu.Lock()
	st.logs = append(st.logs, s)
	st.mu.Unlock()
}

func (st *runState) finish(status, errMsg string) {
	st.mu.Lock()
	st.Status = status
	st.Err = errMsg
	st.mu.Unlock()
}

func (s *Server) executeScan(st *runState) {
	defer func() {
		if rec := recover(); rec != nil {
			st.log(fmt.Sprintf("ERROR: internal panic: %v", rec))
			st.finish("failed", fmt.Sprintf("internal panic: %v", rec))
			log.Printf("[webui] scan %s panicked: %v", st.ID, rec)
		}

		st.mu.Lock()
		status := st.Status
		st.mu.Unlock()
		if status == "completed" {
			s.mu.Lock()
			delete(s.running, st.ID)
			s.mu.Unlock()
		}
	}()

	logCapture := newLogCapture(st)
	defer logCapture.Restore()

	if st.Request.Mode == "chain" {
		s.executeChain(st)
		return
	}

	st.log(fmt.Sprintf("starting %s against context %q", st.Request.Mode, st.Request.Context))
	opts := runner.Options{
		Context:            st.Request.Context,
		Kubeconfig:         st.Request.Kubeconfig,
		Namespace:          st.Request.Namespace,
		Mode:               st.Request.Mode,
		ExploitLevel:       exploiter.ParseLevel(st.Request.Level),
		DisableSafetyGuard: st.Request.DisableSafetyGuard,
		TrivyEnabled:       st.Request.EnableTrivy,
		NucleiEnabled:      st.Request.EnableNuclei,
		Stealth:            st.Request.EnableStealth,
		RuntimeExtras:      st.Request.EnableRuntimeExtras,
		CNIExtras:          st.Request.EnableCNIExtras,
		RefreshThreatIntel: st.Request.RefreshThreatIntel,
		Profile:            st.Request.Profile,
		OnSession: func(sess *kubectx.Session, g *kubectx.ReadOnlyGuard) {
			s.mu.Lock()
			s.sessions[st.ID] = sess
			if g != nil {
				s.guards[st.ID] = g
				if s.AllowLiveExploit {
					g.AllowLiveExec = true
					g.AllowPodCreate = true
					g.AllowPodDelete = true
				}
			}
			s.mu.Unlock()
		},
	}

	if len(st.Request.ExclusionYAML) > 0 {
		if set, err := policy.ParseExclusions([]byte(st.Request.ExclusionYAML)); err != nil {
			st.log("WARN: could not parse exclusions: " + err.Error())
		} else {
			opts.Exclusions = set
			st.log(fmt.Sprintf("loaded %d exclusion rule(s)", len(set.Entries)))
		}
	}
	if opts.Mode == "chain" && strings.TrimSpace(st.Request.ExclusionYAML) != "" {
		st.log("NOTE: exclusions are validated but not applied in chain mode")
	}
	if opts.Mode == "scan" {
		opts.SkipExploit = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	report, err := runner.Execute(ctx, opts)
	if err != nil {
		st.log("ERROR: " + err.Error())
		st.finish("failed", err.Error())
		return
	}
	report.Metadata.ScanID = st.ID

	if st.Request.MinSeverity != "" {
		report.Findings = filterBySeverity(report.Findings, st.Request.MinSeverity)
	}
	if st.Request.HideFP {
		report.Findings = filterOutFP(report.Findings)
	}
	report.Summary = scanner.ComputeSummary(report.Findings)
	report.Summary.Accepted = len(report.AcceptedFindings)

	st.Report = report
	s.store.Save(st.ID, st.Request, report)
	s.persistReport(st.ID, st.Request, report)
	st.log(fmt.Sprintf("done: %d findings (critical=%d high=%d exploited=%d)",
		report.Summary.Total,
		report.Summary.BySeverity[scanner.SevCritical],
		report.Summary.BySeverity[scanner.SevHigh],
		report.Summary.Exploited))
	st.finish("completed", "")
}

func filterBySeverity(fs []scanner.Finding, min string) []scanner.Finding {
	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	limit, ok := order[strings.ToUpper(min)]
	if !ok {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if order[string(f.Severity)] <= limit {
			out = append(out, f)
		}
	}
	return out
}

func filterOutFP(fs []scanner.Finding) []scanner.Finding {
	out := fs[:0]
	for _, f := range fs {
		if f.Exploit != nil && f.Exploit.FalsePositive {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (s *Server) handleChainCleanup(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	s.mu.Lock()
	eng := s.chainEngines[scanID]
	s.mu.Unlock()
	if eng == nil {
		writeError(w, 404, fmt.Errorf("no chain engine for scan %s", scanID))
		return
	}
	eng.Cleanup()
	s.mu.Lock()
	delete(s.chainEngines, scanID)
	s.mu.Unlock()
	writeJSON(w, 200, map[string]string{"status": "cleaned up"})
}

func (s *Server) handleChainPods(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	s.repMu.RLock()
	rep, ok := s.store.Get(scanID)
	if !ok {
		s.repMu.RUnlock()
		writeError(w, 404, fmt.Errorf("scan %s not found", scanID))
		return
	}

	var shells []map[string]string
	for _, f := range rep.Findings {
		if f.RuleID == "KH-CHAIN-SHELL" {
			shells = append(shells, map[string]string{
				"findingId": f.ID,
				"pod":       f.Resource.Name,
				"namespace": f.Resource.Namespace,
				"title":     f.Title,
			})
		}
	}
	s.repMu.RUnlock()
	writeJSON(w, 200, map[string]any{"pods": shells})
}

func (s *Server) executeChain(st *runState) {
	defer func() {
		if rec := recover(); rec != nil {
			st.log(fmt.Sprintf("ERROR: internal panic: %v", rec))
			st.finish("failed", fmt.Sprintf("internal panic: %v", rec))
			log.Printf("[webui] chain scan %s panicked: %v", st.ID, rec)
		}
	}()
	st.log(fmt.Sprintf("starting CHAIN MODE against context %q", st.Request.Context))
	st.log("═══════════════════════════════════════════════════════")
	st.log("  Autonomous Attack Chain: privesc → escape → harvest → lateral → control-plane")
	st.log("═══════════════════════════════════════════════════════")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	cleanupSess, err := kubectx.Resolve(st.Request.Context, st.Request.Kubeconfig)
	if err != nil {
		st.log("ERROR: " + err.Error())
		st.finish("failed", err.Error())
		return
	}
	st.log(fmt.Sprintf("connected: cluster=%s server=%s", cleanupSess.Info.ClusterName, cleanupSess.Info.ClusterServer))

	sess, guard, err := kubectx.WrapSessionReadOnly(cleanupSess)
	if err != nil {
		st.log("ERROR enabling mandatory chain safety guard: " + err.Error())
		st.finish("failed", err.Error())
		return
	}
	configureChainGuard(guard)
	st.log("mandatory chain safety guard: DELETE blocked; pod CREATE, pod exec, and pods/ephemeralcontainers PATCH allowed")

	s.mu.Lock()
	s.sessions[st.ID] = sess
	s.guards[st.ID] = guard
	s.mu.Unlock()

	inv, err := scanner.BuildInventory(ctx, sess, st.Request.Namespace)
	if err != nil {
		st.log("ERROR building inventory: " + err.Error())
		st.finish("failed", err.Error())
		return
	}
	st.log(fmt.Sprintf("inventory: pods=%d nodes=%d namespaces=%d", len(inv.Pods), len(inv.Nodes), len(inv.Namespaces)))

	advisor := chainexploit.NewAdvisor("none", "", "", "")

	eng := chainexploit.NewEngine(sess, inv, chainexploit.Options{
		Timeout:  15 * time.Minute,
		Advisor:  advisor,
		KeepPods: true,
	})
	eng.SetCleanupSession(cleanupSess)

	chainReport := eng.Run(ctx)

	s.mu.Lock()
	s.chainEngines[st.ID] = eng
	s.mu.Unlock()

	report := &scanner.ScanReport{
		Metadata: scanner.ScanMetadata{
			ScanID:            st.ID,
			ContextName:       sess.Info.Name,
			ClusterName:       sess.Info.ClusterName,
			ClusterServer:     sess.Info.ClusterServer,
			User:              sess.Info.UserName,
			ServerVersion:     sess.Info.ServerVersion,
			Platform:          sess.Info.Platform,
			Namespace:         st.Request.Namespace,
			StartedAt:         chainReport.StartedAt,
			FinishedAt:        chainReport.FinishedAt,
			DurationMillis:    chainReport.FinishedAt.Sub(chainReport.StartedAt).Milliseconds(),
			Mode:              "chain",
			SafetyGuard:       true,
			NamespacesChecked: inv.NamespaceTargets,
			CollectionIssues:  inv.CollectionIssues,
			Incomplete:        len(inv.CollectionIssues) > 0,
		},
		Findings: chainReport.Findings,
		Graph:    chainReport.Graph,
	}
	for _, violation := range guard.Violations() {
		report.Metadata.SafetyViolations = append(
			report.Metadata.SafetyViolations,
			violation.Method+" "+violation.Path,
		)
	}

	chainSev := scanner.SevInfo
	if chainReport.FullChainProven {
		chainSev = scanner.SevCritical
	} else if chainReport.MaxAccess != "INITIAL" {
		chainSev = scanner.SevHigh
	}
	report.Findings = append([]scanner.Finding{{
		ID:          "KH-CHAIN-SUMMARY-" + st.ID,
		RuleID:      "KH-CHAIN-SUMMARY",
		Category:    scanner.CatEscape,
		Severity:    chainSev,
		Title:       fmt.Sprintf("Attack Chain Result: %s (max access: %s)", chainReport.Duration, chainReport.MaxAccess),
		Description: chainReport.ChainSummary,
		Resource:    scanner.Resource{Kind: "Cluster", Name: sess.Info.ClusterName},
		Evidence:    chainReport.ChainSummary,
		Tags:        []string{"chain", "autonomous", "summary"},
	}}, report.Findings...)

	report.Summary = scanner.ComputeSummary(report.Findings)

	st.Report = report
	s.store.Save(st.ID, st.Request, report)
	s.persistReport(st.ID, st.Request, report)
	st.log(chainReport.ChainSummary)
	st.log(fmt.Sprintf("chain complete: max_access=%s steps=%d credentials=%d findings=%d",
		chainReport.MaxAccess, len(chainReport.Steps), len(chainReport.Credentials), len(report.Findings)))
	st.finish("completed", "")
}

func configureChainGuard(guard *kubectx.ReadOnlyGuard) {
	guard.AllowLiveExec = true
	guard.AllowPodCreate = true
	guard.AllowPodDelete = false
	guard.AllowSidecarPatch = false

	guard.AllowEphemeralPatch = true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func writeBodyError(w http.ResponseWriter, err error, limit int64) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeError(w, 413, fmt.Errorf("request body too large (max %d bytes)", mbe.Limit))
		return
	}
	writeError(w, 400, fmt.Errorf("invalid request body: %w", err))
}

func setSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
}

func sseSend(w http.ResponseWriter, event string, data any) {
	var payload string
	switch v := data.(type) {
	case string:
		payload = v
	default:
		b, _ := json.Marshal(v)
		payload = string(b)
	}
	fmt.Fprintf(w, "event: %s\n", event)
	for _, line := range strings.Split(payload, "\n") {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprint(w, "\n")
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"allowLiveExploit":      s.AllowLiveExploit,
		"allowSidecarInjection": s.AllowSidecarInjection,
	})
}

func (s *Server) findFinding(scanID, findingID string) (*scanner.ScanReport, *scanner.Finding) {
	rep, ok := s.store.Get(scanID)
	if !ok {
		return nil, nil
	}
	for i := range rep.Findings {
		if rep.Findings[i].ID == findingID {
			finding := rep.Findings[i]
			return rep, &finding
		}
	}
	return nil, nil
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	findingID := r.PathValue("fid")
	s.repMu.RLock()
	rep, f := s.findFinding(scanID, findingID)
	var caps []liveexploit.Capability
	clusterName := ""
	if rep != nil && f != nil {
		clusterName = rep.Metadata.ClusterName
		caps = liveexploit.CapabilitiesFor(*f)
	}
	s.repMu.RUnlock()
	if rep == nil || f == nil {
		writeError(w, 404, fmt.Errorf("finding not found"))
		return
	}
	out := make([]liveexploit.Capability, 0, len(caps))
	for _, c := range caps {
		if c.RequiresSidecarFlag && !s.AllowSidecarInjection {
			continue
		}
		out = append(out, c)
	}
	writeJSON(w, 200, map[string]any{
		"clusterName":    clusterName,
		"liveExploitOn":  s.AllowLiveExploit,
		"sidecarAllowed": s.AllowSidecarInjection,
		"capabilities":   out,
	})
}

type liveExploitReq struct {
	Capability  string            `json:"capability"`
	Inputs      map[string]string `json:"inputs"`
	ConfirmText string            `json:"confirmText"`
}

func (s *Server) handleLiveExploit(w http.ResponseWriter, r *http.Request) {
	if !s.AllowLiveExploit {
		writeError(w, 403, fmt.Errorf("live-exploit disabled on this server (start with --live-exploit)"))
		return
	}
	scanID := r.PathValue("id")
	findingID := r.PathValue("fid")
	s.repMu.RLock()
	rep, f := s.findFinding(scanID, findingID)
	clusterName := ""
	if rep != nil && f != nil {
		clusterName = rep.Metadata.ClusterName
	}
	s.repMu.RUnlock()
	if rep == nil || f == nil {
		writeError(w, 404, fmt.Errorf("finding not found"))
		return
	}
	var body liveExploitReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAcceptBodyBytes)).Decode(&body); err != nil {
		writeError(w, 400, fmt.Errorf("invalid request body: %w", err))
		return
	}
	if body.ConfirmText == "" || body.ConfirmText != clusterName {
		writeError(w, 400, fmt.Errorf("cluster-name confirmation mismatch (expected %q)", clusterName))
		return
	}

	offered := liveexploit.CapabilitiesFor(*f)
	var chosen *liveexploit.Capability
	for i := range offered {
		if offered[i].ID == body.Capability {
			chosen = &offered[i]
			break
		}
	}
	if chosen == nil {
		writeError(w, 400, fmt.Errorf("capability %q is not available for this finding", body.Capability))
		return
	}
	if chosen.RequiresSidecarFlag && !s.AllowSidecarInjection {
		writeError(w, 403, fmt.Errorf("sidecar injection capability requires --allow-sidecar-injection"))
		return
	}

	s.mu.Lock()
	sess := s.sessions[scanID]
	guard := s.guards[scanID]
	s.mu.Unlock()
	if sess == nil {
		writeError(w, 409, fmt.Errorf("no live session for scan %s (restart a scan first)", scanID))
		return
	}

	if guard != nil {
		guard.AllowLiveExec = true
		if chosen.RequiresSidecarFlag {
			guard.AllowSidecarPatch = true
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	res := liveexploit.Execute(ctx, sess, f, liveexploit.Options{
		CapabilityID:          body.Capability,
		Inputs:                body.Inputs,
		AllowSidecarInjection: s.AllowSidecarInjection,
	})
	if guard != nil {
		guard.AllowLiveExec = false
		guard.AllowSidecarPatch = false
	}

	bundle := &scanner.EvidenceBundle{
		Command:  res.Command,
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		Data:     res.Data,
		Duration: res.FinishedAt.Sub(res.StartedAt).String(),
		Request: map[string]any{
			"scanId":     scanID,
			"findingId":  f.ID,
			"capability": body.Capability,
			"inputs":     body.Inputs,
		},
		Response: map[string]any{
			"evidence": res.Evidence,
			"error":    res.Err,
			"ok":       res.Err == "",
		},
		ExitCode: res.ExitCode,
	}
	entry := scanner.LiveExploitEntry{
		At:             time.Now(),
		FindingID:      f.ID,
		RuleID:         f.RuleID,
		Capability:     body.Capability,
		Ok:             res.Err == "",
		Evidence:       res.Evidence,
		Error:          res.Err,
		EvidenceBundle: bundle,
	}
	s.repMu.Lock()
	s.store.AppendLiveExploit(scanID, entry)
	s.repMu.Unlock()

	writeJSON(w, 200, res)
}

func (s *Server) shellTarget(r *http.Request) (*scanner.ScanReport, *scanner.Finding, *kubectx.Session, int, error) {
	if !s.AllowLiveExploit {
		return nil, nil, nil, http.StatusForbidden, fmt.Errorf("interactive shells are disabled on this server (--live-exploit was not enabled); no shell was opened")
	}
	s.repMu.RLock()
	rep, finding := s.findFinding(r.PathValue("id"), r.PathValue("fid"))
	s.repMu.RUnlock()
	if rep == nil || finding == nil {
		return nil, nil, nil, http.StatusNotFound, fmt.Errorf("finding not found; scan reports survive restarts, live sessions do not")
	}
	if confirm := r.URL.Query().Get("confirm"); confirm == "" || confirm != rep.Metadata.ClusterName {
		return nil, nil, nil, http.StatusBadRequest, fmt.Errorf("cluster-name confirmation mismatch")
	}
	offered := false
	for _, capability := range liveexploit.CapabilitiesFor(*finding) {
		offered = offered || capability.ID == "pod-shell"
	}
	if !offered {
		return nil, nil, nil, http.StatusBadRequest, fmt.Errorf("pod-shell is not available for this finding")
	}
	s.mu.Lock()
	session := s.sessions[r.PathValue("id")]
	s.mu.Unlock()
	if session == nil || session.RestCfg == nil {
		return nil, nil, nil, http.StatusConflict, fmt.Errorf("no retained live session for this scan; a server restart cannot restore it")
	}
	return rep, finding, session, http.StatusOK, nil
}

func (s *Server) handleShellStatus(w http.ResponseWriter, r *http.Request) {
	_, finding, session, status, err := s.shellTarget(r)
	if err != nil {
		writeError(w, status, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_, container, err := liveexploit.CheckPodShellTarget(ctx, session, finding)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	scope := "container"
	if finding.Shell != nil {
		scope = finding.Shell.Scope
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available": true, "container": container, "scope": scope,
		"rexecAvailable": podexec.FindPlugin() != "",
		"note":           "Pod/container are running. Standard pods/exec is tried first; if it fails (some clusters' exec admission webhooks mandate an audited exec plugin instead), the tool retries through kubectl-rexec automatically.",
	})
}

func (s *Server) handleShell(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	_, f, sess, status, targetErr := s.shellTarget(r)
	if targetErr != nil {
		writeError(w, status, targetErr)
		return
	}

	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[shell] ws upgrade failed: %v", err)
		return
	}
	defer ws.Close()

	log.Printf("[shell] opening pods/exec to %s/%s (finding=%s scan=%s)",
		f.Resource.Namespace, f.Resource.Name, f.ID, scanID)

	_ = ws.WriteMessage(websocket.TextMessage,
		[]byte(fmt.Sprintf("[kube-dementor] attaching to %s/%s…\r\n", f.Resource.Namespace, f.Resource.Name)))

	ctx, cancel := context.WithCancel(kubectx.WithPodExecPermission(r.Context()))
	defer cancel()

	err = liveexploit.StartPodShell(ctx, sess, f, ws)
	if err != nil {
		log.Printf("[shell] session ended: %v", err)
		_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\n[kube-dementor] "+err.Error()+"\r\n"))
	} else {
		log.Printf("[shell] session ended cleanly")
	}

	entry := scanner.LiveExploitEntry{
		At:         time.Now(),
		FindingID:  f.ID,
		RuleID:     f.RuleID,
		Capability: "pod-shell",
		Ok:         err == nil,
		Evidence:   fmt.Sprintf("interactive shell to %s/%s", f.Resource.Namespace, f.Resource.Name),
	}
	if err != nil {
		entry.Error = err.Error()
	}
	s.repMu.Lock()
	s.store.AppendLiveExploit(scanID, entry)
	s.repMu.Unlock()
}
