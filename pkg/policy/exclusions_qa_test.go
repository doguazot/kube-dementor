package policy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func TestParseExclusionsRejectsBadInputsLoudly(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"empty", "", "empty"},
		{"whitespace", "   \n\t ", "empty"},
		{"malformed yaml", "rules: [\n broken", "yaml parse"},
		{"malformed json", "{rules: ", "parse"},
		{"zero rules yaml", "version: 1\nrules: []", "no rules"},
		{"zero rules json", `{}`, "no rules"},
		{"notes only", "version: 1\nnotes: nothing", "no rules"},
		{"rule without ruleId", "rules:\n  - namespaces: [x]", "missing ruleId"},
		{"bad regex", "rules:\n  - ruleIdPattern: '[unclosed'", "invalid ruleIdPattern"},
		{"bad namePattern", "rules:\n  - ruleId: X\n    namePattern: '*('", "invalid namePattern"},
		{"bad severityMin", "rules:\n  - ruleId: X\n    severityMin: urgent", "invalid severityMin"},
		{"severityMin typo suppresses nothing silently", "rules:\n  - ruleId: X\n    severityMin: HIG", "invalid severityMin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := ParseExclusions([]byte(tc.data))
			if err == nil {
				t.Fatalf("expected error for %q, got set %+v", tc.data, set)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseExclusionsAcceptsAllSupportedShapes(t *testing.T) {
	shapes := []string{
		"rules:\n  - ruleId: KH-WRK-001\n    reason: expected",
		"version: 1\nrules:\n  - ruleIdPattern: ^KH-SEC-.*$\n    namespaces: [legacy, team]",
		`[{"ruleId":"KH-WRK-001","namespaces":["x"]}]`,
		"{rules: [{ruleId: KH-WRK-001}]}",
		"rules:\n  - ruleId: X\n    resourceKinds: [Pod, Secret]\n    namePattern: '^debug-.*$'\n    severityMin: medium",
		"rules:\n  - ruleId: X\n    severityMin: LOW",
	}
	for _, shape := range shapes {
		set, err := ParseExclusions([]byte(shape))
		if err != nil {
			t.Fatalf("shape %q must parse: %v", shape, err)
		}
		if len(set.Entries) != 1 {
			t.Fatalf("expected 1 rule from %q, got %d", shape, len(set.Entries))
		}
	}
}

func TestExclusionMatchingSemantics(t *testing.T) {
	set, err := ParseExclusions([]byte(`
rules:
  - ruleId: KH-WRK-001
    namespaces: [team]
  - ruleIdPattern: ^KH-SEC-.*$
    severityMin: high
`))
	if err != nil {
		t.Fatal(err)
	}

	critical := scanner.Finding{RuleID: "KH-WRK-001", Severity: scanner.SevCritical, Resource: scanner.Resource{Namespace: "team"}}
	low := scanner.Finding{RuleID: "KH-WRK-001", Severity: scanner.SevLow, Resource: scanner.Resource{Namespace: "team"}}
	otherNs := scanner.Finding{RuleID: "KH-WRK-001", Severity: scanner.SevCritical, Resource: scanner.Resource{Namespace: "other"}}
	secLow := scanner.Finding{RuleID: "KH-SEC-002", Severity: scanner.SevLow}
	secHigh := scanner.Finding{RuleID: "KH-SEC-002", Severity: scanner.SevHigh}

	if set.Match(critical) == nil || set.Match(low) == nil {
		t.Fatal("exact ruleId must match regardless of severity")
	}
	if set.Match(otherNs) != nil {
		t.Fatal("namespace filter must exclude other namespaces")
	}
	if set.Match(secLow) != nil {
		t.Fatal("severityMin high must suppress only HIGH and above")
	}
	if set.Match(secHigh) == nil {
		t.Fatal("high finding must match pattern rule with severityMin high")
	}
}

func TestApplyMarksSuppressedFindingsWithReason(t *testing.T) {
	set, err := ParseExclusions([]byte("rules:\n  - ruleId: KH-WRK-001\n    reason: expected privileged pod"))
	if err != nil {
		t.Fatal(err)
	}
	findings := []scanner.Finding{
		{RuleID: "KH-WRK-001", Severity: scanner.SevHigh},
		{RuleID: "KH-SEC-002", Severity: scanner.SevLow},
	}
	active, suppressed, hits := set.Apply(findings)
	if len(active) != 1 || len(suppressed) != 1 {
		t.Fatalf("expected 1 active 1 suppressed, got %d/%d", len(active), len(suppressed))
	}
	if !suppressed[0].Accepted || suppressed[0].AcceptedScope != "exclusion" {
		t.Fatalf("suppressed finding must be marked accepted: %+v", suppressed[0])
	}
	if suppressed[0].AcceptedReason != "expected privileged pod" {
		t.Fatalf("reason must be carried: %q", suppressed[0].AcceptedReason)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 rule hit, got %v", hits)
	}

	var nilSet *ExclusionSet
	active, suppressed, _ = nilSet.Apply(findings)
	if len(active) != 2 || suppressed != nil {
		t.Fatal("nil exclusion set must pass everything through")
	}
	if nilSet.Match(findings[0]) != nil {
		t.Fatal("nil set must not match")
	}
}

func TestGlobalAcceptsSurviveConcurrentWritesAndDedupe(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = AddGlobalAccept(scanner.GlobalAcceptance{Signature: "sig", RuleID: "KH-1", Reason: "r"})
			if err := AddGlobalAccept(scanner.GlobalAcceptance{Signature: "sig", RuleID: "KH-1", Reason: "updated"}); err != nil {
				t.Errorf("add: %v", err)
			}
			if err := RemoveGlobalAccept("sig"); err != nil {
				t.Errorf("remove: %v", err)
			}
		}(i)
	}
	wg.Wait()

	list, err := LoadGlobalAccepts()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected all accepts to be removed, got %d", len(list))
	}

	if err := AddGlobalAccept(scanner.GlobalAcceptance{Signature: "sig-2", RuleID: "KH-2"}); err != nil {
		t.Fatal(err)
	}
	if err := AddGlobalAccept(scanner.GlobalAcceptance{Signature: "sig-2", RuleID: "KH-2", Reason: "again"}); err != nil {
		t.Fatal(err)
	}
	list, err = LoadGlobalAccepts()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Reason != "again" {
		t.Fatalf("same signature must dedupe and update, got %+v", list)
	}
}

func TestGlobalAcceptsRefuseToOverwriteCorruptFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".kube-dementor"), 0o700); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("}{ not json")
	path := filepath.Join(home, ".kube-dementor", "accepted.json")
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AddGlobalAccept(scanner.GlobalAcceptance{Signature: "sig", RuleID: "KH-1"}); err == nil {
		t.Fatal("add must fail on a corrupt store instead of overwriting it")
	}
	if err := RemoveGlobalAccept("sig"); err == nil {
		t.Fatal("remove must fail on a corrupt store instead of overwriting it")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(corrupt) {
		t.Fatalf("corrupt store must stay untouched, got %q err=%v", string(data), err)
	}
}

func TestApplyGlobalAcceptsMatchesBySignature(t *testing.T) {
	findings := []scanner.Finding{
		{RuleID: "KH-WRK-001", Resource: scanner.Resource{Kind: "Pod", Namespace: "team", Name: "a"}},
		{RuleID: "KH-WRK-001", Resource: scanner.Resource{Kind: "Pod", Namespace: "team", Name: "b"}, Signature: "prefilled-sig"},
		{RuleID: "KH-WRK-002", Resource: scanner.Resource{Kind: "Pod", Namespace: "team", Name: "c"}},
	}
	active, accepted := ApplyGlobalAccepts(findings, []scanner.GlobalAcceptance{
		{Signature: Signature(findings[0]), By: "qa", Reason: "known"},
		{Signature: "prefilled-sig", By: "qa2", Reason: "prefilled"},
	})
	if len(active) != 1 || len(accepted) != 2 {
		t.Fatalf("expected 1 active 2 accepted, got %d/%d", len(active), len(accepted))
	}
	if accepted[0].AcceptedBy != "qa" || accepted[0].AcceptedScope != "global" {
		t.Fatalf("acceptance metadata wrong: %+v", accepted[0])
	}
	if accepted[1].AcceptedBy != "qa2" {
		t.Fatalf("prefilled signature must win: %+v", accepted[1])
	}
	if active[0].RuleID != "KH-WRK-002" {
		t.Fatalf("wrong findings accepted: %+v", accepted)
	}
}
