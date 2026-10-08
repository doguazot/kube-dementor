package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	rbacv1 "k8s.io/api/rbac/v1"
)

func ImpersonationRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-RBAC-IMP-001", Title: "Identity impersonation grant", Category: scanner.CatRBAC, Fn: ruleImpersonationGrant},
		{ID: "KH-RBAC-IMP-002", Title: "Impersonation over system:masters / cluster-admin", Category: scanner.CatRBAC, Fn: ruleMasterImpersonation},
		{ID: "KH-RBAC-IMP-003", Title: "Impersonation over wildcard identities", Category: scanner.CatRBAC, Fn: ruleWildcardImpersonation},
	}
}

type impersonateRule struct {
	kind      string
	name      string
	namespace string
	targets   []string
	resources []string
	verbs     []string
	hasWild   bool
}

func collectImpersonateRules(inv *scanner.Inventory) []impersonateRule {
	var out []impersonateRule
	walk := func(kind, name, ns string, rules []rbacv1.PolicyRule) {
		for _, r := range rules {
			if !sliceHasAny(r.Verbs, "impersonate", "*") {
				continue
			}
			imp := impersonateRule{
				kind:      kind,
				name:      name,
				namespace: ns,
				verbs:     r.Verbs,
				resources: r.Resources,
			}
			for _, res := range r.Resources {
				if res != "users" && res != "groups" && res != "serviceaccounts" && res != "uids" && res != "*" {
					continue
				}
				names := r.ResourceNames
				if len(names) == 0 {
					names = []string{"*"}
				}
				for _, n := range names {
					if n == "*" {
						imp.hasWild = true
					}
					imp.targets = append(imp.targets, fmt.Sprintf("%s/%s", res, n))
				}
			}
			if len(imp.targets) > 0 {
				out = append(out, imp)
			}
		}
	}
	for _, r := range inv.Roles {
		walk("Role", r.Name, r.Namespace, r.Rules)
	}
	for _, r := range inv.ClusterRoles {
		walk("ClusterRole", r.Name, "", r.Rules)
	}
	return out
}

func holdersOf(inv *scanner.Inventory, roleKind, roleNs, roleName string) []string {
	var out []string
	for _, crb := range inv.ClusterRoleBindings {
		if crb.RoleRef.Kind != "ClusterRole" {
			continue
		}
		if roleKind != "ClusterRole" || crb.RoleRef.Name != roleName {
			continue
		}
		for _, s := range crb.Subjects {
			out = append(out, subjectPretty(s))
		}
	}
	for _, rb := range inv.RoleBindings {
		kind := rb.RoleRef.Kind
		if kind == "ClusterRole" && roleKind == "ClusterRole" && rb.RoleRef.Name == roleName {
			for _, s := range rb.Subjects {
				out = append(out, subjectPretty(s)+fmt.Sprintf(" (RoleBinding in ns/%s)", rb.Namespace))
			}
		}
		if kind == "Role" && roleKind == "Role" && rb.Namespace == roleNs && rb.RoleRef.Name == roleName {
			for _, s := range rb.Subjects {
				out = append(out, subjectPretty(s))
			}
		}
	}
	sort.Strings(out)
	return dedupeStrings(out)
}

func subjectPretty(s rbacv1.Subject) string {
	switch s.Kind {
	case "ServiceAccount":
		return fmt.Sprintf("SA/%s/%s", s.Namespace, s.Name)
	case "User":
		return fmt.Sprintf("User/%s", s.Name)
	case "Group":
		return fmt.Sprintf("Group/%s", s.Name)
	}
	return fmt.Sprintf("%s/%s", s.Kind, s.Name)
}

func dedupeStrings(ss []string) []string {
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

func ruleImpersonationGrant(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, ir := range collectImpersonateRules(inv) {
		holders := holdersOf(inv, ir.kind, ir.namespace, ir.name)
		sev := scanner.SevHigh
		if ir.hasWild || hasBadTarget(ir.targets) {
			sev = scanner.SevCritical
		}

		evLines := []string{
			fmt.Sprintf("%s %q (verbs=%v resources=%v)", ir.kind, ir.name, ir.verbs, ir.resources),
			"Can become:",
		}
		for _, t := range ir.targets {
			evLines = append(evLines, "  • "+t)
		}
		if len(holders) > 0 {
			evLines = append(evLines, "", "Held by:")
			for _, h := range holders {
				evLines = append(evLines, "  ⇽ "+h)
			}
		} else {
			evLines = append(evLines, "", "Held by: (no current bindings — still a loaded gun; anyone who can bind/escalate this role fires it)")
		}
		out = append(out, scanner.Finding{
			RuleID:   "KH-RBAC-IMP-001",
			Category: scanner.CatRBAC,
			Severity: sev,
			Title:    fmt.Sprintf("%s %q grants impersonate — %d holder(s) could pivot into %d identity target(s)", ir.kind, ir.name, len(holders), len(ir.targets)),
			Description: `Impersonation is the single most common "hidden admin" path in a Kubernetes cluster. ` +
				"Whoever holds this role can call the apiserver as somebody else — most importantly as `system:masters`, which is cluster-admin-equivalent and never shows up in RBAC listings. " +
				"Audit logs attribute the subsequent actions to the *impersonated* identity, so the real attacker disappears from post-incident review.",
			Resource:       scanner.Resource{Kind: ir.kind, Namespace: ir.namespace, Name: ir.name},
			Evidence:       strings.Join(evLines, "\n"),
			Impact:         "Silent privilege escalation to any identity the holder is permitted to impersonate — including `system:masters` if not restricted by `resourceNames`.",
			Recommendation: "Remove the impersonate verb; or if unavoidable, restrict resourceNames to a small, known set (e.g. a specific break-glass SA) and never list users/groups wildcards.",
			References:     []string{"https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation", "MITRE T1134 (Access Token Manipulation)", "MITRE T1078 (Valid Accounts)"},
			MitreATTACK:    []string{"T1134", "T1078"},
			Tags:           []string{"rbac", "impersonate", "privesc", "audit-blind"},
		})
	}
	return out
}

func hasBadTarget(ts []string) bool {
	for _, t := range ts {
		if strings.Contains(t, "system:masters") || strings.Contains(t, "cluster-admin") {
			return true
		}
	}
	return false
}

func ruleMasterImpersonation(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, ir := range collectImpersonateRules(inv) {
		hits := []string{}
		for _, t := range ir.targets {
			if strings.Contains(t, "system:masters") || strings.Contains(t, "cluster-admin") {
				hits = append(hits, t)
			}
		}
		if len(hits) == 0 {
			continue
		}
		holders := holdersOf(inv, ir.kind, ir.namespace, ir.name)
		out = append(out, scanner.Finding{
			RuleID:   "KH-RBAC-IMP-002",
			Category: scanner.CatRBAC,
			Severity: scanner.SevCritical,
			Title:    fmt.Sprintf("%s %q can impersonate system:masters / cluster-admin", ir.kind, ir.name),
			Resource: scanner.Resource{Kind: ir.kind, Namespace: ir.namespace, Name: ir.name},
			Description: "This role can act as `system:masters` (the built-in group hard-wired to full cluster-admin) or as the `cluster-admin` user. " +
				"RBAC controllers will NOT list this as a cluster-admin binding, but the functional equivalence is 1:1 — plus the audit log attributes the actions to `system:masters` rather than to the actual caller.",
			Evidence:       fmt.Sprintf("targets=%v  ·  held by %v", hits, holders),
			Impact:         "Undetectable cluster-admin compromise.",
			Recommendation: "Remove this rule. There is no legitimate reason to grant impersonate on system:masters.",
			References:     []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings"},
			MitreATTACK:    []string{"T1134", "T1078"},
			Tags:           []string{"rbac", "impersonate", "cluster-admin", "audit-blind"},
		})
	}
	return out
}

func ruleWildcardImpersonation(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, ir := range collectImpersonateRules(inv) {
		if !ir.hasWild {
			continue
		}
		holders := holdersOf(inv, ir.kind, ir.namespace, ir.name)
		out = append(out, scanner.Finding{
			RuleID:         "KH-RBAC-IMP-003",
			Category:       scanner.CatRBAC,
			Severity:       scanner.SevCritical,
			Title:          fmt.Sprintf("%s %q grants impersonate over any identity (wildcard)", ir.kind, ir.name),
			Resource:       scanner.Resource{Kind: ir.kind, Namespace: ir.namespace, Name: ir.name},
			Description:    "No resourceNames means the holder can impersonate **any** identity in the cluster, including `system:masters`. This is equivalent to cluster-admin but invisible to the standard RBAC listings.",
			Evidence:       fmt.Sprintf("verbs=%v resources=%v targets=%v · held by %v", ir.verbs, ir.resources, ir.targets, holders),
			Impact:         "Full cluster takeover via audit-laundered impersonation.",
			Recommendation: "Scope resourceNames to a small set of break-glass identities, or remove the verb entirely.",
			MitreATTACK:    []string{"T1134"},
			Tags:           []string{"rbac", "impersonate", "wildcard", "privesc"},
		})
	}
	return out
}
