package runner

import (
	"context"
	"crypto/sha1"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/attackpath"
	"github.com/kube-dementor/kube-dementor/pkg/evasion"
	"github.com/kube-dementor/kube-dementor/pkg/exploiter"
	"github.com/kube-dementor/kube-dementor/pkg/identity"
	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/policy"
	"github.com/kube-dementor/kube-dementor/pkg/profile"
	"github.com/kube-dementor/kube-dementor/pkg/rbacutil"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
	"github.com/kube-dementor/kube-dementor/pkg/scanner/rules"
	"github.com/kube-dementor/kube-dementor/pkg/threatintel"
)

type Options struct {
	Context      string
	Kubeconfig   string
	Namespace    string
	Mode         string
	ExploitLevel exploiter.Level
	SkipExploit  bool

	DisableSafetyGuard bool

	NucleiEnabled bool
	NucleiBinary  string
	NucleiTargets []string

	TrivyEnabled bool
	TrivyBinary  string

	Stealth bool

	RuntimeExtras bool

	CNIExtras bool

	OnSession func(*kubectx.Session, *kubectx.ReadOnlyGuard)

	Exclusions *policy.ExclusionSet

	RefreshThreatIntel bool

	Profile string
}

func Execute(ctx context.Context, opts Options) (*scanner.ScanReport, error) {
	started := time.Now()

	sess, err := kubectx.Resolve(opts.Context, opts.Kubeconfig)
	if err != nil {
		return nil, err
	}
	return executeSession(ctx, opts, sess, started)
}

func executeSession(ctx context.Context, opts Options, sess *kubectx.Session, started time.Time) (*scanner.ScanReport, error) {
	log.Printf("[runner] connected: context=%s cluster=%s server=%s version=%s",
		sess.Info.Name, sess.Info.ClusterName, sess.Info.ClusterServer, sess.Info.ServerVersion)

	var guard *kubectx.ReadOnlyGuard
	if !opts.DisableSafetyGuard {
		guardedSess, g, err := kubectx.WrapSessionReadOnly(sess)
		if err != nil {
			return nil, fmt.Errorf("enable safety guard: %w", err)
		} else {
			sess = guardedSess
			guard = g
			log.Printf("[runner] safety-guard: active (DELETE/PATCH/UPDATE and non-dry-run CREATE are blocked)")
		}
	} else {
		log.Printf("[runner] safety-guard: DISABLED by --no-safety-guard (mutations are NOT blocked)")
	}

	if opts.OnSession != nil {
		opts.OnSession(sess, guard)
	}

	var intel threatintel.Freshness
	var kev *threatintel.KEV
	if opts.RefreshThreatIntel || opts.TrivyEnabled || opts.NucleiEnabled {
		intel = threatintel.Collect(ctx, opts.TrivyEnabled, opts.NucleiEnabled)
		if len(intel.Warnings) > 0 {
			for _, w := range intel.Warnings {
				log.Printf("[threatintel] %s", w)
			}
		}
	}
	if k, err := threatintel.LoadCachedKEV(); err == nil && k != nil {
		kev = k
		log.Printf("[threatintel] CISA KEV loaded: %d entries (fetched %s)", len(k.Entries), k.FetchedAt.Format(time.RFC3339))
	}

	report := &scanner.ScanReport{
		Metadata: scanner.ScanMetadata{
			ScanID:        fmt.Sprintf("kh-%d", time.Now().UnixMilli()),
			ContextName:   sess.Info.Name,
			ClusterName:   sess.Info.ClusterName,
			ClusterServer: sess.Info.ClusterServer,
			User:          sess.Info.UserName,
			ServerVersion: sess.Info.ServerVersion,
			Platform:      sess.Info.Platform,
			Namespace:     opts.Namespace,
			StartedAt:     started,
			Mode:          opts.Mode,
		},
	}

	inv, err := scanner.BuildInventory(ctx, sess, opts.Namespace)
	if err != nil {
		return nil, fmt.Errorf("build inventory: %w", err)
	}
	report.Metadata.TargetsScanned = len(inv.Pods) + len(inv.Namespaces) + len(inv.Roles) + len(inv.ClusterRoles)

	nsList := collectNamespaces(inv)

	if opts.Namespace != "" {
		seen := false
		for _, n := range nsList {
			if n == opts.Namespace {
				seen = true
				break
			}
		}
		if !seen {
			nsList = append(nsList, opts.Namespace)
		}
	}
	sort.Strings(nsList)
	report.Metadata.NamespacesChecked = nsList
	selfPerms := exploiter.DiscoverSelfPermissions(ctx, sess, nsList)
	report.Identity = buildIdentitySnapshot(ctx, sess, inv, selfPerms)

	ident, idErr := identity.Resolve(ctx, sess.Client, nsList)
	if idErr != nil {
		log.Printf("[identity] resolve failed (continuing with limited data): %v", idErr)
	}
	if ident != nil {
		mergeResolvedIntoIdentity(&report.Identity, ident)

		if ident.User != "" {
			report.Metadata.User = ident.User
		}
		for _, warning := range ident.Warnings {
			inv.CollectionIssues = append(inv.CollectionIssues, scanner.CollectionIssue{
				Resource: "identity", Operation: "review", Error: warning,
			})
		}
	}

	graph := attackpath.Build(inv)
	username := ""
	meNode := "Operator/" + sess.Info.Name
	var groups, impUsers, impGroups, impSAs []string
	if ident != nil && ident.User != "" {
		username, groups = ident.User, ident.Groups
		impUsers, impGroups, impSAs = ident.ImpersonatableUsers, ident.ImpersonatableGroups, ident.ImpersonatableServiceAccounts
	} else {
		report.Identity.DiscoverySource = "kubeconfig-label (authentication identity unresolved)"
		graph.Nodes[meNode] = &attackpath.Node{
			ID: meNode, Kind: "Operator", Name: "current credentials (authentication identity unresolved)",
		}
	}
	if username != "" {
		meNode = attackpath.AddIdentity(graph, username, groups, impUsers, impGroups, impSAs)
	}

	ssarResults := attackpath.FanOut(ctx, sess.Client, nsList, nil)

	attackpath.AugmentRules(graph, meNode, report.Identity.NamespacedRules, inv)
	if meNode != "" {
		n := attackpath.AugmentGraph(graph, meNode, ssarResults)
		log.Printf("[attackpath] identity overlay: %d action node(s) added, groups=%d", n, len(groups))
	}
	for _, result := range ssarResults {
		if result.Error != "" {
			inv.CollectionIssues = append(inv.CollectionIssues, scanner.CollectionIssue{
				Resource: result.Check.Resource, Namespace: result.Namespace,
				Operation: "authorize " + result.Check.Verb, Error: result.Error,
			})
		}
	}
	createNamespaces := podCreateNamespaces(nsList, ssarResults, report.Identity.NamespacedRules)
	inv.PodAdmission = scanner.AssessPodCreation(ctx, sess.Client, createNamespaces, inv.Nodes, opts.Mode != "discover")
	attackpath.AugmentPodCreation(graph, meNode, inv.PodAdmission)
	report.Findings = append(report.Findings, scanner.PodCreationFindings(inv.PodAdmission)...)
	inv.EphemeralAssessment = scanner.AssessEphemeralContainers(ctx, sess.Client, inv)
	report.Findings = append(report.Findings, scanner.EphemeralFindings(inv.EphemeralAssessment)...)
	attackpath.AugmentEphemeralContainers(graph, meNode, inv.EphemeralAssessment)
	inv.CollectionIssues = append(inv.CollectionIssues, scanner.EphemeralCollectionIssues(inv.EphemeralAssessment)...)
	for _, result := range inv.PodAdmission {
		if result.Status == scanner.AdmissionUnknown && opts.Mode != "discover" {
			inv.CollectionIssues = append(inv.CollectionIssues, scanner.CollectionIssue{
				Resource: "pods", Namespace: result.Namespace, Operation: "admission dry-run", Error: result.Reason,
			})
		}
	}
	report.Metadata.CollectionIssues = inv.CollectionIssues
	report.Metadata.Incomplete = len(inv.CollectionIssues) > 0
	if finding := scanner.CollectionFinding(inv.CollectionIssues); finding != nil {
		report.Findings = append(report.Findings, *finding)
	}

	starts := append(seedSubjects(inv, username), meNode)
	if ident != nil {
		if meNode != "" {
			starts = append(starts, meNode)
		}
		for _, grp := range ident.Groups {
			starts = append(starts, fmt.Sprintf("Group/%s", grp))
		}
	}
	starts = dedupe(starts)
	paths := attackpath.FindFrom(graph, starts, 6)
	if meNode == "" {
		meNode = meNodeID(sess.Info.UserName, starts)
	}
	report.Graph = attackpath.Snapshot(graph, paths, meNode)

	if meNode != "" {
		before := len(report.Findings)
		attackpath.ApplyToReport(report, meNode, ssarResults)
		log.Printf("[runner] identity findings added: %d -> %d (meNode=%q nsRules=%d ssar=%d)",
			before, len(report.Findings), meNode, len(report.Identity.NamespacedRules), len(ssarResults))
	}

	if opts.Mode == "discover" {
		if len(paths) > 0 {
			aggressive := false
			report.Findings = append(report.Findings, attackpath.ToFindings(paths, aggressive)...)
			log.Printf("[discover] %d attack-path(s) from %d seed subject(s)", len(report.Findings), len(starts))
		}
		report.Metadata.EscapePosture = computeEscapePosture(report.Findings)
		if report.Metadata.EscapePosture == "no-known-escape" {

			report.Metadata.EscapePosture = "unknown"
		}
		scanner.SortFindings(report.Findings)
		assignFindingIDs(report.Findings)
		for i := range report.Findings {
			report.Findings[i].Signature = policy.Signature(report.Findings[i])
		}
		if opts.Exclusions != nil {
			active, suppressed, rulesHit := opts.Exclusions.Apply(report.Findings)
			report.Findings = active
			report.AcceptedFindings = append(report.AcceptedFindings, suppressed...)
			if len(rulesHit) > 0 {
				report.Metadata.ExclusionsApplied = rulesHit
			}
		}
		globals, _ := policy.LoadGlobalAccepts()
		var gacc []scanner.Finding
		report.Findings, gacc = policy.ApplyGlobalAccepts(report.Findings, globals)
		report.AcceptedFindings = append(report.AcceptedFindings, gacc...)
		report.Metadata.Acceptances = buildAcceptances(nil, gacc)
		report.Summary = scanner.ComputeSummary(report.Findings)
		report.Summary.Accepted = len(report.AcceptedFindings)
		report.Metadata.FinishedAt = time.Now()
		report.Metadata.DurationMillis = time.Since(started).Milliseconds()
		if guard != nil {
			report.Metadata.SafetyGuard = true
		}
		return report, nil
	}

	sc := scanner.New()
	sc.Register(rules.WorkloadRules()...)
	sc.Register(rules.RBACRules()...)
	sc.Register(rules.SecretRules()...)
	sc.Register(rules.SecretDeepRules()...)
	sc.Register(rules.SATokenRules()...)
	sc.Register(rules.NetworkRules()...)
	sc.Register(rules.NetPolSimulatorRules()...)
	sc.Register(rules.ClusterRules()...)
	sc.Register(rules.AdmissionRules()...)
	sc.Register(rules.CloudRules()...)
	sc.Register(rules.EscapeRules()...)
	sc.Register(rules.PersistenceRules()...)
	sc.Register(rules.MeshRules()...)
	sc.Register(rules.ExposedDashboardRules()...)
	sc.Register(rules.AdvancedPrivescRules()...)
	sc.Register(rules.AdvancedWorkloadRules()...)
	sc.Register(rules.AdvancedSecretRules()...)
	sc.Register(rules.AdvancedNetworkRules()...)
	sc.Register(rules.AdvancedSARules()...)
	sc.Register(rules.ClusterAdvancedRules()...)
	report.Metadata.RulesEvaluated = len(sc.Rules())

	findings := sc.Scan(inv, sess)

	if len(report.Findings) > 0 {
		findings = append(findings, report.Findings...)
		report.Findings = nil
	}

	var surface *evasion.DetectionSurface
	if opts.Stealth {
		var evFindings []scanner.Finding
		surface, evFindings = evasion.Scan(ctx, sess, inv)
		findings = append(findings, evFindings...)
		findings = append(findings, evasion.AuditRecon(ctx, sess, inv)...)
		findings = append(findings, evasion.CatalogFindings(surface)...)
		log.Printf("[evasion] detection-surface worst=%s edrs=%d", surface.Worst, len(surface.EDRs))
	}

	if (opts.Mode == "scan" || opts.Mode == "exploit") && len(paths) > 0 {
		aggressive := surface != nil && surface.Worst == "aggressive"
		pathFindings := attackpath.ToFindings(paths, aggressive)
		log.Printf("[attackpath] %d path(s) from %d seed subject(s) (edr-aggressive=%v)",
			len(pathFindings), len(starts), aggressive)
		findings = append(findings, pathFindings...)
	}

	if opts.RuntimeExtras {
		findings = append(findings, rules.RuntimeRulesStatic(inv)...)
		findings = append(findings, rules.RuntimeExtrasMore(inv)...)
	}

	if opts.CNIExtras {
		findings = append(findings, rules.CNIRulesStatic(inv)...)
	}

	if !opts.SkipExploit && opts.Mode == "exploit" {
		ex := exploiter.New(sess, opts.ExploitLevel)

		ex.SelfPerms(ctx, nsList)
		findings = ex.Run(ctx, inv, findings)
	}

	if opts.NucleiEnabled {
		extra, err := runNucleiPhase(ctx, sess, inv, opts)
		if err != nil {
			log.Printf("[runner] nuclei: %v", err)
		}
		findings = append(findings, extra...)
		report.Metadata.ExternalScanners = append(report.Metadata.ExternalScanners, "nuclei")
	}
	if opts.TrivyEnabled {
		extra, err := runTrivyPhase(ctx, inv, opts)
		if err != nil {
			log.Printf("[runner] trivy: %v", err)
		}
		findings = append(findings, extra...)
		report.Metadata.ExternalScanners = append(report.Metadata.ExternalScanners, "trivy")
	}

	if kev != nil {
		for i := range findings {
			for _, cve := range extractCVEs(findings[i].Evidence + " " + findings[i].Title + " " + findings[i].Description) {
				if entry := kev.LookupCVE(cve); entry != nil {
					findings[i].Severity = scanner.SevCritical
					findings[i].Tags = append(findings[i].Tags, "KEV:"+cve)
					if !strings.Contains(findings[i].Impact, "KEV") {
						findings[i].Impact = "CISA KEV: known exploited in the wild. " + findings[i].Impact
					}
					_ = entry
				}
			}
		}
	}

	if pKind := profile.Parse(opts.Profile); pKind == profile.Internal {
		demoted := profile.Apply(pKind, findings)
		if demoted > 0 {
			log.Printf("[profile] internal-trust: demoted %d/%d finding(s) by one severity step", demoted, len(findings))
		}
		report.Metadata.Profile = string(pKind)
	} else {
		report.Metadata.Profile = string(profile.External)
	}

	report.Metadata.EscapePosture = computeEscapePosture(findings)

	if opts.Namespace != "" {
		filtered := findings[:0]
		for _, f := range findings {
			ns := f.Resource.Namespace
			if ns == "" || ns == opts.Namespace || strings.HasPrefix(f.RuleID, "KH-IDENT-") || strings.HasPrefix(f.RuleID, "KH-ESC-POSTURE") {
				filtered = append(filtered, f)
			}
		}
		log.Printf("[runner] namespace filter %q: %d -> %d findings", opts.Namespace, len(findings), len(filtered))
		findings = filtered
	}

	scanner.SortFindings(findings)
	assignFindingIDs(findings)

	for i := range findings {
		findings[i].Signature = policy.Signature(findings[i])
	}
	var suppressed []scanner.Finding
	var rulesHit []string
	if opts.Exclusions != nil {
		findings, suppressed, rulesHit = opts.Exclusions.Apply(findings)
	}
	globals, _ := policy.LoadGlobalAccepts()
	var globAccepted []scanner.Finding
	findings, globAccepted = policy.ApplyGlobalAccepts(findings, globals)
	report.Findings = findings
	report.Summary = scanner.ComputeSummary(findings)
	report.Summary.Accepted = len(suppressed) + len(globAccepted)
	report.Metadata.Acceptances = buildAcceptances(suppressed, globAccepted)
	if len(rulesHit) > 0 {
		report.Metadata.ExclusionsApplied = rulesHit
	}

	report.AcceptedFindings = append(suppressed, globAccepted...)

	if guard != nil {
		violations := guard.Violations()
		if len(violations) > 0 {
			report.Metadata.SafetyViolations = make([]string, len(violations))
			for i, v := range violations {
				report.Metadata.SafetyViolations[i] = v.Method + " " + v.Path
			}
			log.Printf("[runner] WARN: safety-guard intercepted %d mutation attempt(s)", len(violations))
		}
		report.Metadata.SafetyGuard = true
	}

	report.Metadata.FinishedAt = time.Now()
	report.Metadata.DurationMillis = time.Since(started).Milliseconds()
	if kev != nil || intel.TrivyDBAt.After(time.Time{}) || intel.NucleiAt.After(time.Time{}) {
		ti := &scanner.ThreatIntelStatus{
			TrivyDBUpdated:  intel.TrivyDBAt,
			NucleiTemplates: intel.NucleiAt,
			Warnings:        intel.Warnings,
		}
		if kev != nil {
			ti.KEVFetched = kev.FetchedAt
			ti.KEVEntries = len(kev.Entries)
		}
		report.Metadata.ThreatIntel = ti
	}
	return report, nil
}

func computeEscapePosture(findings []scanner.Finding) string {
	exploited := false
	vulnerable := false
	unknown := false
	for _, f := range findings {
		if f.AttackPath != nil {
			for _, edge := range f.AttackPath.Edges {
				if edge.Kind == string(attackpath.EdgeCanEscape) {
					vulnerable = true
				}
			}
		}
		if f.RuleID == "KH-AUDIT-COVERAGE" {
			unknown = true
		}
		if f.RuleID == "KH-ESC-POD-CREATE" {
			for _, tag := range f.Tags {
				if tag == "admission-unknown" {
					unknown = true
				}
			}
		}
		if !strings.HasPrefix(f.RuleID, "KH-ESC-") {
			continue
		}
		if f.RuleID == "KH-ESC-POSTURE" {
			continue
		}
		if f.Exploit != nil && f.Exploit.Exploited {
			exploited = true
		}
		switch f.Severity {
		case scanner.SevCritical, scanner.SevHigh:
			vulnerable = true
		}
	}
	if exploited {
		return "exploited"
	}
	if vulnerable {
		return "vulnerable"
	}
	if unknown {
		return "unknown"
	}
	return "no-known-escape"
}

func extractCVEs(s string) []string {
	var out []string
	i := 0
	for i < len(s)-3 {
		if (s[i] == 'C' || s[i] == 'c') && strings.HasPrefix(strings.ToUpper(s[i:]), "CVE-") {
			j := i + 4
			for j < len(s) && (s[j] == '-' || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			if j-i >= 12 {
				out = append(out, strings.ToUpper(s[i:j]))
			}
			i = j
			continue
		}
		i++
	}
	return out
}

func mergeResolvedIntoIdentity(snap *scanner.IdentitySnapshot, id *identity.Identity) {
	if id == nil || snap == nil {
		return
	}
	if id.User != "" {
		snap.Username = id.User
	}
	snap.UID = id.UID

	seen := map[string]bool{}
	for _, g := range snap.Groups {
		seen[g] = true
	}
	for _, g := range id.Groups {
		if !seen[g] {
			snap.Groups = append(snap.Groups, g)
			seen[g] = true
		}
	}
	snap.ImpersonatableUsers = id.ImpersonatableUsers
	snap.ImpersonatableGroups = id.ImpersonatableGroups
	snap.ImpersonatableServiceAccounts = id.ImpersonatableServiceAccounts
	snap.TokenRequestSAs = id.TokenRequestSAs
	snap.DiscoverySource = id.DiscoverySource
	if len(id.ImpersonatableUsers)+len(id.ImpersonatableGroups)+len(id.ImpersonatableServiceAccounts) > 0 {
		snap.CanImpersonate = true
	}
	if len(id.NamespacedRules) > 0 {
		snap.NamespacedRules = make(map[string][]scanner.NamespacedRule, len(id.NamespacedRules))
		for ns, rules := range id.NamespacedRules {
			for _, r := range rules {
				snap.NamespacedRules[ns] = append(snap.NamespacedRules[ns], scanner.NamespacedRule{
					Verbs:           r.Verbs,
					APIGroups:       r.APIGroups,
					Resources:       r.Resources,
					ResourceNames:   r.ResourceNames,
					NonResourceURLs: r.NonResourceURLs,
				})
			}
		}
	}
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	out := ss[:0:0]
	for _, s := range ss {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func meNodeID(username string, seeds []string) string {
	if strings.HasPrefix(username, "system:serviceaccount:") {
		parts := strings.Split(username[len("system:serviceaccount:"):], ":")
		if len(parts) == 2 {
			return fmt.Sprintf("ServiceAccount/%s/%s", parts[0], parts[1])
		}
	}
	if username != "" {
		return "User/" + username
	}
	if len(seeds) > 0 {
		return seeds[0]
	}
	return ""
}

func buildAcceptances(fromExclusion, fromGlobal []scanner.Finding) []scanner.Acceptance {
	out := make([]scanner.Acceptance, 0, len(fromExclusion)+len(fromGlobal))
	now := time.Now()
	for _, f := range fromExclusion {
		out = append(out, scanner.Acceptance{
			FindingID: f.ID, RuleID: f.RuleID, Signature: f.Signature,
			By: f.AcceptedBy, Reason: f.AcceptedReason, At: now, Scope: "exclusion",
		})
	}
	for _, f := range fromGlobal {
		out = append(out, scanner.Acceptance{
			FindingID: f.ID, RuleID: f.RuleID, Signature: f.Signature,
			By: f.AcceptedBy, Reason: f.AcceptedReason, At: now, Scope: "global",
		})
	}
	return out
}

func assignFindingIDs(findings []scanner.Finding) {
	seen := make(map[string]int, len(findings))
	for i := range findings {
		rid := findings[i].RuleID
		if rid == "" {
			rid = "FX"
		}
		target := findings[i].Resource.String()
		ev := findings[i].Evidence
		if len(ev) > 120 {
			ev = ev[:120]
		}
		base := fmt.Sprintf("%s::%s::%s", rid, target, ev)
		h := sha1.Sum([]byte(base))
		id := fmt.Sprintf("f-%s-%x", rid, h[:5])
		if n := seen[id]; n > 0 {
			id = fmt.Sprintf("%s-%d", id, n)
		}
		seen[id]++
		findings[i].ID = id
	}
}

func seedSubjects(inv *scanner.Inventory, username string) []string {
	seen := map[string]bool{}
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
		}
	}
	for _, crb := range inv.ClusterRoleBindings {
		for _, s := range crb.Subjects {
			if s.Kind == "ServiceAccount" {
				add(fmt.Sprintf("ServiceAccount/%s/%s", s.Namespace, s.Name))
			} else if s.Kind == "User" {
				add(fmt.Sprintf("User/%s", s.Name))
			} else if s.Kind == "Group" {
				add(fmt.Sprintf("Group/%s", s.Name))
			}
		}
	}
	for _, rb := range inv.RoleBindings {
		for _, s := range rb.Subjects {
			if s.Kind == "ServiceAccount" {
				ns := s.Namespace
				if ns == "" {
					ns = rb.Namespace
				}
				add(fmt.Sprintf("ServiceAccount/%s/%s", ns, s.Name))
			} else if s.Kind == "User" {
				add("User/" + s.Name)
			} else if s.Kind == "Group" {
				add("Group/" + s.Name)
			}
		}
	}
	if strings.HasPrefix(username, "system:serviceaccount:") {
		parts := strings.Split(username[len("system:serviceaccount:"):], ":")
		if len(parts) == 2 {
			add(fmt.Sprintf("ServiceAccount/%s/%s", parts[0], parts[1]))
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func collectNamespaces(inv *scanner.Inventory) []string {
	set := map[string]bool{}
	for _, ns := range inv.NamespaceTargets {
		set[ns] = true
	}
	for _, ns := range inv.Namespaces {
		set[ns.Name] = true
	}
	for _, p := range inv.Pods {
		set[p.Namespace] = true
	}
	for _, sa := range inv.ServiceAccounts {
		set[sa.Namespace] = true
	}
	for _, role := range inv.Roles {
		set[role.Namespace] = true
	}
	for _, binding := range inv.RoleBindings {
		set[binding.Namespace] = true
	}
	var out []string
	for n := range set {
		if n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func podCreateNamespaces(namespaces []string, results []attackpath.CanDoResult, rules map[string][]scanner.NamespacedRule) []string {
	allowed := map[string]bool{}
	for _, result := range results {
		check := result.Check
		if !result.Allowed || result.Error != "" || check.Group != "" ||
			check.Verb != "create" || check.Resource != "pods" || check.Subresource != "" || check.Name != "" {
			continue
		}
		if result.Namespace == "" {
			for _, ns := range namespaces {
				allowed[ns] = true
			}
		} else {
			allowed[result.Namespace] = true
		}
	}
	for ns, nsRules := range rules {
		for _, rule := range nsRules {
			if rbacutil.Matches(rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames, "", "pods", "", "create", "") {
				allowed[ns] = true
			}
		}
	}
	out := make([]string, 0, len(allowed))
	for ns := range allowed {
		if ns != "" {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

func buildIdentitySnapshot(ctx context.Context, sess *kubectx.Session, inv *scanner.Inventory, sp *exploiter.SelfPermissions) scanner.IdentitySnapshot {
	snap := scanner.IdentitySnapshot{
		Username: sess.Info.UserName,
	}
	snap.IsClusterAdmin = sp.IsClusterAdmin
	snap.CanExecPods = sp.CanExecPodsAny
	snap.CanImpersonate = sp.CanImpersonate
	snap.CanPortForward = anyNS(sp, "create", "pods", "portforward")

	for ns, m := range sp.PerNamespace {
		if ns == "" {
			continue
		}
		for _, v := range m {
			if v {
				snap.NamespaceAccess = append(snap.NamespaceAccess, ns)
				break
			}
		}
	}

	if sp.Allowed("list", "secrets", "", "") {
		snap.AccessibleSecrets = len(inv.Secrets)
	} else {

		for ns, m := range sp.PerNamespace {
			if m["list:secrets"] {
				for _, s := range inv.Secrets {
					if s.Namespace == ns {
						snap.AccessibleSecrets++
					}
				}
			}
		}
	}
	if sp.Allowed("list", "pods", "", "") {
		snap.AccessiblePods = len(inv.Pods)
	} else {
		for ns, m := range sp.PerNamespace {
			if m["list:pods"] {
				for _, p := range inv.Pods {
					if p.Namespace == ns {
						snap.AccessiblePods++
					}
				}
			}
		}
	}

	verbSet := map[string]bool{}
	highRisk := []string{
		"create:pods", "create:pods/exec", "create:pods/attach", "create:pods/portforward",
		"list:secrets", "get:secrets", "create:secrets",
		"impersonate:users", "impersonate:serviceaccounts", "impersonate:groups",
		"create:clusterrolebindings", "create:rolebindings",
		"bind:clusterroles", "escalate:clusterroles",
		"approve:signers", "update:certificatesigningrequests/approval",
		"get:nodes/proxy",
	}
	for _, key := range highRisk {
		if sp.ClusterScope[key] {
			verbSet[key] = true
		}
	}
	for ns, m := range sp.PerNamespace {
		_ = ns
		for _, key := range highRisk {
			if m[key] {
				verbSet[key] = true
			}
		}
	}
	for k := range verbSet {
		snap.HighRiskVerbs = append(snap.HighRiskVerbs, k)
	}

	sort.Strings(snap.NamespaceAccess)
	sort.Strings(snap.HighRiskVerbs)
	return snap
}

func anyNS(sp *exploiter.SelfPermissions, verb, resource, sub string) bool {
	key := verb + ":" + resource
	if sub != "" {
		key = verb + ":" + resource + "/" + sub
	}
	if sp.ClusterScope[key] {
		return true
	}
	for _, m := range sp.PerNamespace {
		if m[key] {
			return true
		}
	}
	return false
}

var _ = strings.Contains
