package attackpath

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type CanDoCheck struct {
	Verb        string
	Group       string
	Resource    string
	Subresource string
	Name        string
	Label       string
	HV          bool
}

func DefaultCanDoChecks() []CanDoCheck {
	return []CanDoCheck{
		{Verb: "list", Resource: "secrets", Label: "list secrets", HV: true},
		{Verb: "get", Resource: "secrets", Label: "read any secret", HV: true},
		{Verb: "create", Resource: "pods", Subresource: "exec", Label: "exec into pods", HV: true},
		{Verb: "create", Resource: "pods", Label: "create pods", HV: true},
		{Verb: "update", Resource: "pods", Subresource: "ephemeralcontainers", Label: "attach debug containers", HV: true},
		{Verb: "patch", Resource: "pods", Subresource: "ephemeralcontainers", Label: "patch debug containers", HV: true},
		{Verb: "impersonate", Resource: "users", Label: "impersonate users", HV: true},
		{Verb: "impersonate", Resource: "groups", Label: "impersonate groups", HV: true},
		{Verb: "impersonate", Resource: "serviceaccounts", Label: "impersonate SAs", HV: true},
		{Verb: "create", Resource: "serviceaccounts", Subresource: "token", Label: "issue SA tokens", HV: true},
		{Verb: "create", Resource: "tokenreviews", Group: "authentication.k8s.io", Label: "TokenReview"},
		{Verb: "update", Resource: "deployments", Group: "apps", Label: "update deployments"},
		{Verb: "patch", Resource: "configmaps", Label: "patch configmaps"},
	}
}

type CanDoResult struct {
	Namespace string
	Check     CanDoCheck
	Allowed   bool
	Error     string
}

func FanOut(ctx context.Context, client kubernetes.Interface, namespaces []string, checks []CanDoCheck) []CanDoResult {
	if len(checks) == 0 {
		checks = DefaultCanDoChecks()
	}
	type job struct {
		ns string
		c  CanDoCheck
		i  int
	}
	var wg sync.WaitGroup

	set := map[string]bool{"": true}
	for _, ns := range namespaces {
		set[ns] = true
	}
	nss := make([]string, 0, len(set))
	for ns := range set {
		nss = append(nss, ns)
	}
	sort.Strings(nss)
	results := make([]CanDoResult, len(nss)*len(checks))
	jobs := make(chan job, len(results))
	for _, ns := range nss {
		for _, c := range checks {
			jobs <- job{ns: ns, c: c, i: len(jobs)}
		}
	}
	close(jobs)
	const workers = 8
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				ok, err := ssarAllowed(ctx, client, j.ns, j.c)
				result := CanDoResult{Namespace: j.ns, Check: j.c, Allowed: ok}
				if err != nil {
					result.Error = err.Error()
				}
				results[j.i] = result
			}
		}()
	}
	start := time.Now()
	wg.Wait()
	log.Printf("[attackpath/ssar] %d SSAR probe(s) across %d namespace(s) in %s",
		len(nss)*len(checks), len(nss), time.Since(start))
	return results
}

func ssarAllowed(ctx context.Context, client kubernetes.Interface, ns string, c CanDoCheck) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace:   ns,
				Verb:        c.Verb,
				Group:       c.Group,
				Resource:    c.Resource,
				Subresource: c.Subresource,
				Name:        c.Name,
			},
		},
	}
	res, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, r, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	if !res.Status.Allowed && res.Status.EvaluationError != "" {
		return false, fmt.Errorf("authorization evaluation: %s", res.Status.EvaluationError)
	}
	return res.Status.Allowed, nil
}

func AugmentGraph(g *Graph, me string, results []CanDoResult) (actionNodes int) {
	if me == "" {
		return 0
	}
	for _, r := range results {
		if !r.Allowed || r.Error != "" {
			continue
		}
		actionID := actionNodeID(r)
		if _, ok := g.Nodes[actionID]; !ok {
			actionNodes++
		}
		addActionNode(g, r)
		note := fmt.Sprintf("SSAR=yes %s %s/%s",
			r.Check.Verb, nonEmpty(r.Check.Group, "core"), subjectDesc(r.Check))
		g.addEdge(me, actionID, EdgeCanDo, note)
		connectEffectiveAccess(g, me, r)
	}
	return
}

func addActionNode(g *Graph, r CanDoResult) {
	name := r.Check.Label
	if r.Namespace != "" {
		name = fmt.Sprintf("%s in ns/%s", name, r.Namespace)
	} else {
		name += " (all namespaces / cluster scope)"
	}
	g.addNode(&Node{ID: actionNodeID(r), Kind: "Action", Namespace: r.Namespace, Name: name, HighValue: r.Check.HV})
}

func connectEffectiveAccess(g *Graph, holder string, r CanDoResult) {
	for _, node := range g.Nodes {
		if r.Namespace != "" && node.Namespace != r.Namespace {
			continue
		}
		if r.Check.Name != "" && node.Name != r.Check.Name {
			continue
		}
		c := r.Check
		if c.Group != "" {
			continue
		}
		switch {
		case node.Kind == KindPod && c.Resource == "pods" && c.Subresource == "exec" && (c.Verb == "create" || c.Verb == "get"):
			g.addEdge(holder, node.ID, EdgeGrantsExec, "SSAR-authorized pods/exec")
		case node.Kind == KindPod && c.Resource == "pods" && c.Subresource == "ephemeralcontainers" && (c.Verb == "update" || c.Verb == "patch"):
			g.addEdge(holder, node.ID, EdgeCanInjectEphemeral, "SSAR-authorized debug-container mutation; admission, startup and exec/attach unverified")
		case node.Kind == KindSecret && c.Resource == "secrets" && (c.Verb == "get" || c.Verb == "list" || c.Verb == "watch"):
			g.addEdge(holder, node.ID, EdgeGrantsRead, "SSAR-authorized secret access")
		case node.Kind == KindServiceAccount && c.Resource == "serviceaccounts" && c.Subresource == "token" && c.Verb == "create":
			g.addEdge(holder, node.ID, EdgeCanTokenRequest, "SSAR-authorized TokenRequest; token audience unverified")
		case node.Kind == KindServiceAccount && c.Resource == "pods" && c.Subresource == "" && c.Verb == "create":
			g.addEdge(holder, node.ID, EdgeCanTokenRequest, "create pod using this SA; admission and token availability unverified")
		}
	}
}

func AugmentPodCreation(g *Graph, me string, results []scanner.PodAdmissionResult) {
	for _, result := range results {
		if me == "" || result.Status != scanner.AdmissionAdmitted {
			continue
		}
		name := result.Technique
		if result.NodeName != "" {
			name += " on " + result.NodeName
		}
		pid := nodeID("PodTemplate", result.Namespace, name)
		g.addNode(&Node{ID: pid, Kind: "PodTemplate", Namespace: result.Namespace, Name: name})
		g.addEdge(me, pid, EdgeCanDo, "RBAC authorized; dangerous specification admitted by dry-run; no pod created")
		target := nodeID("NodeAccess", result.Namespace, "unplaced")
		kind, ns, targetName := NodeKind("NodeAccess"), result.Namespace, "potential node access (placement unverified)"
		if result.NodeName != "" {
			target, kind, ns, targetName = nodeID(KindNode, "", result.NodeName), KindNode, "", result.NodeName
		}
		g.addNode(&Node{ID: target, Kind: kind, Namespace: ns, Name: targetName, HighValue: true})
		note := "potential escape if scheduled and runtime permits; not executed"
		if result.ControlPlane {
			note += "; control-plane targeting admitted, credential access unverified"
		}
		g.addEdge(pid, target, EdgeCanEscape, note)
	}
}

func actionNodeID(r CanDoResult) string {
	ns := r.Namespace
	if ns == "" {
		ns = "*"
	}
	return fmt.Sprintf("Action/%s/%s:%s/%s/%s/%s", ns, r.Check.Verb, r.Check.Resource, r.Check.Subresource, r.Check.Group, r.Check.Name)
}

func AugmentEphemeralContainers(g *Graph, me string, results []scanner.EphemeralAssessment) {
	if me == "" {
		return
	}
	snapshot := scanner.EphemeralPotentialGraph(results, me)
	for _, node := range snapshot.Nodes {
		if node.ID == me {
			continue
		}
		g.addNode(&Node{
			ID: node.ID, Kind: NodeKind(node.Kind), Namespace: node.Namespace,
			Name: node.Name, HighValue: node.HighValue, Status: node.Status, Detail: node.Detail,
		})
	}
	for _, edge := range snapshot.Edges {
		g.addEdge(edge.From, edge.To, EdgeKind(edge.Kind), edge.Note)
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func subjectDesc(c CanDoCheck) string {
	if c.Subresource != "" {
		return c.Resource + "/" + c.Subresource
	}
	return c.Resource
}

func ApplyToReport(rep *scanner.ScanReport, me string, results []CanDoResult) {
	if rep == nil || me == "" {
		return
	}

	emitNamespacedRulesFindings(rep, me)
	var allowedHV []CanDoResult
	var allowed []CanDoResult
	var unknown []CanDoResult
	for _, r := range results {
		if r.Error != "" {
			unknown = append(unknown, r)
		} else if r.Allowed {
			allowed = append(allowed, r)
			if r.Check.HV {
				allowedHV = append(allowedHV, r)
			}
		}
	}
	if len(allowed) == 0 {
		description := "The authorization API denied the specific checks that completed. This bounded probe set does not prove there are no other permissions or attack paths. Authorization checks do not evaluate pod admission."
		title := fmt.Sprintf("Effective permissions for %s — %d probe(s), zero allowed", me, len(results))
		tags := []string{"identity", "effective-permissions", "ssar", "zero-allowed"}
		if len(unknown) > 0 || len(results) == 0 {
			description = "Authorization coverage is incomplete. Failed or unperformed reviews are unknown, not permission denials; this assessment cannot establish that the identity is safe."
			title = fmt.Sprintf("Effective permissions for %s are incomplete (%d unknown)", me, len(unknown))
			tags = append(tags, "incomplete")
		}

		rep.Findings = append(rep.Findings, scanner.Finding{
			ID:          "KH-IDENT-CANDO",
			RuleID:      "KH-IDENT-CANDO",
			Category:    scanner.CatRBAC,
			Severity:    scanner.SevInfo,
			Title:       title,
			Resource:    scanner.Resource{Kind: "Identity", Name: me},
			Description: description,
			Evidence:    summariseProbesTried(results),
			Impact:      "Only the completed authorization checks were assessed; other capabilities and admission decisions may be unknown.",
			Tags:        tags,
			DetectedAt:  time.Now(),
		})
		return
	}
	sev := scanner.SevHigh
	if len(allowedHV) == 0 {
		sev = scanner.SevInfo
	}
	var lines []string
	for _, r := range allowed {
		scope := "cluster-scope"
		if r.Namespace != "" {
			scope = "ns/" + r.Namespace
		}
		marker := "·"
		if r.Check.HV {
			marker = "★"
		}
		lines = append(lines, fmt.Sprintf(" %s %s [%s]", marker, r.Check.Label, scope))
	}
	for _, r := range unknown {
		lines = append(lines, fmt.Sprintf(" ? %s [ns/%s]: %s", r.Check.Label, r.Namespace, r.Error))
	}
	fnd := scanner.Finding{
		ID:          "KH-IDENT-CANDO",
		RuleID:      "KH-IDENT-CANDO",
		Category:    scanner.CatRBAC,
		Severity:    sev,
		Title:       fmt.Sprintf("Effective permissions for %s (%d yes / %d total)", me, len(allowed), len(results)),
		Description: "SelfSubjectAccessReview reports authorization for this identity in each scope. It does not evaluate admission webhooks, Pod Security Admission, scheduling, or runtime isolation. Starred entries are sensitive capabilities, not proof of cluster compromise.",
		Resource: scanner.Resource{
			Kind: "Identity",
			Name: me,
		},
		Evidence:       joinLines(lines),
		Impact:         "An attacker controlling this identity gains the confirmed permissions in their reported scope. Further escalation depends on accessible resources, admission and runtime constraints.",
		Recommendation: "Trim the Role/ClusterRole bindings that grant the starred permissions. Keep exec/secret-list/impersonate out of human identities; prefer break-glass credentials that are issued on-demand.",
		Tags:           []string{"identity", "effective-permissions", "ssar"},
		DetectedAt:     time.Now(),
	}
	rep.Findings = append(rep.Findings, fnd)
}

func emitNamespacedRulesFindings(rep *scanner.ScanReport, me string) {
	if rep == nil || rep.Identity.NamespacedRules == nil {
		return
	}
	for ns, rules := range rep.Identity.NamespacedRules {
		if len(rules) == 0 {
			continue
		}

		hv := false
		lines := make([]string, 0, len(rules))
		for _, r := range rules {
			if len(r.Verbs) == 0 {
				continue
			}
			if len(r.Resources) > 0 {
				for _, res := range r.Resources {
					ag := "core"
					if len(r.APIGroups) > 0 && r.APIGroups[0] != "" {
						ag = r.APIGroups[0]
					}
					marker := ""
					if isHVRule(r.Verbs, res) {
						hv = true
						marker = "★ "
					}
					lines = append(lines, fmt.Sprintf("  %s%s  %s (%s)", marker, strings.Join(r.Verbs, ","), res, ag))
				}
			}
			if len(r.NonResourceURLs) > 0 {
				for _, u := range r.NonResourceURLs {
					lines = append(lines, fmt.Sprintf("  %s  %s", strings.Join(r.Verbs, ","), u))
				}
			}
		}
		if len(lines) == 0 {
			continue
		}
		sev := scanner.SevMedium
		if hv {
			sev = scanner.SevHigh
		}
		rep.Findings = append(rep.Findings, scanner.Finding{
			ID:             "KH-IDENT-RULES-" + ns,
			RuleID:         "KH-IDENT-RULES",
			Category:       scanner.CatRBAC,
			Severity:       sev,
			Title:          fmt.Sprintf("Capabilities of %s in ns/%s (%d rule(s))", me, ns, len(rules)),
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns},
			Description:    "Result of `kubectl auth can-i --list -n " + ns + "` — the apiserver's authoritative answer. ★ rules are high-value lateral-movement primitives (secret access, pods/exec, impersonation, token issuance).",
			Evidence:       strings.Join(lines, "\n"),
			Impact:         "Anything listed here is immediately usable by whoever controls this identity.",
			Recommendation: "Remove any ★ rule that the workload does not genuinely require.",
			Tags:           []string{"identity", "ssrr", "namespaced-permissions"},
			DetectedAt:     time.Now(),
		})
	}
}

func isHVRule(verbs []string, resource string) bool {
	for _, v := range verbs {
		switch strings.ToLower(v) {
		case "impersonate":
			return true
		case "create":
			if strings.Contains(resource, "exec") ||
				strings.Contains(resource, "token") ||
				strings.Contains(resource, "ephemeralcontainers") ||
				resource == "pods" {
				return true
			}
		case "get", "list", "watch":
			if resource == "secrets" {
				return true
			}
		case "*":
			return true
		}
	}
	return false
}

func summariseProbesTried(results []CanDoResult) string {
	seen := map[string]bool{}
	var lines []string
	for _, r := range results {
		label := r.Check.Label
		if seen[label] {
			continue
		}
		seen[label] = true
		lines = append(lines, "  - "+label)
	}
	unknown := 0
	for _, result := range results {
		if result.Error != "" {
			unknown++
		}
	}
	return fmt.Sprintf("Asked (%d denied, %d unknown):\n", len(results)-unknown, unknown) + joinLines(lines)
}

func joinLines(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\n"
		}
		out += s
	}
	return out
}

var _ = metav1.CreateOptions{}
