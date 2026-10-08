package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/rbacutil"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	rbacv1 "k8s.io/api/rbac/v1"
)

func RBACRules() []scanner.Rule {
	base := []scanner.Rule{
		{ID: "KH-RBAC-001", Title: "Wildcard permissions (*/*)", Category: scanner.CatRBAC, Fn: ruleRBAC001Wildcard},
		{ID: "KH-RBAC-002", Title: "cluster-admin binding to non-system subject", Category: scanner.CatRBAC, Fn: ruleRBAC002ClusterAdmin},
		{ID: "KH-RBAC-003", Title: "Impersonation rights", Category: scanner.CatRBAC, Fn: ruleRBAC003Impersonate},
		{ID: "KH-RBAC-004", Title: "bind/escalate verbs granted", Category: scanner.CatRBAC, Fn: ruleRBAC004BindEscalate},
		{ID: "KH-RBAC-005", Title: "Broad secret access", Category: scanner.CatRBAC, Fn: ruleRBAC005SecretAccess},
		{ID: "KH-RBAC-006", Title: "Can exec / attach / port-forward into pods", Category: scanner.CatRBAC, Fn: ruleRBAC006PodExec},
		{ID: "KH-RBAC-007", Title: "Can create/patch pods (privilege escalation)", Category: scanner.CatRBAC, Fn: ruleRBAC007PodCreate},
		{ID: "KH-RBAC-008", Title: "system:anonymous or system:unauthenticated granted privileges", Category: scanner.CatRBAC, Fn: ruleRBAC008Anonymous},
		{ID: "KH-RBAC-009", Title: "system:authenticated granted privileges", Category: scanner.CatRBAC, Fn: ruleRBAC009Authenticated},
		{ID: "KH-RBAC-010", Title: "Default SA granted extra privileges", Category: scanner.CatRBAC, Fn: ruleRBAC010DefaultSA},
		{ID: "KH-RBAC-011", Title: "Orphaned RoleBinding (subject does not exist)", Category: scanner.CatRBAC, Fn: ruleRBAC011Orphaned},
		{ID: "KH-RBAC-012", Title: "approve on signers (CSR signing)", Category: scanner.CatRBAC, Fn: ruleRBAC012CSRApprove},
		{ID: "KH-RBAC-013", Title: "nodes/proxy access (kubelet API)", Category: scanner.CatRBAC, Fn: ruleRBAC013NodesProxy},
	}
	return append(base, ImpersonationRules()...)
}

func ruleRBAC001Wildcard(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	eval := func(name, ns string, rules []rbacv1.PolicyRule, isCluster bool) {
		for _, r := range rules {
			if sliceHas(r.Verbs, "*") && sliceHas(r.Resources, "*") {
				kind := "Role"
				if isCluster {
					kind = "ClusterRole"
				}

				if kind == "ClusterRole" && (name == "cluster-admin" || name == "admin" || name == "edit" || name == "system:masters" ||
					strings.HasPrefix(name, "system:controller:") || strings.HasPrefix(name, "system:node") ||
					strings.HasPrefix(name, "system:kube-") || strings.HasPrefix(name, "system:serviceaccount:kube-system:")) {
					continue
				}
				out = append(out, scanner.Finding{
					Severity:       scanner.SevCritical,
					Title:          kind + " grants wildcard verbs on wildcard resources",
					Description:    fmt.Sprintf("%s %q contains a rule with verbs=[*] resources=[*]; any identity bound to it has full access.", kind, name),
					Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
					Evidence:       fmt.Sprintf("rule: apiGroups=%v verbs=* resources=*", r.APIGroups),
					Impact:         "Effectively cluster-admin in the role's scope. Bound subjects can read all secrets, create privileged pods, impersonate, etc.",
					Recommendation: "Split the role by actual API groups/resources needed and use specific verbs. Never use verbs=[*] + resources=[*] in production roles.",
					References:     []string{"CIS 5.1.1"},
					Tags:           []string{"rbac", "wildcard"},
				})
				break
			}
		}
	}
	for _, r := range inv.Roles {
		eval(r.Name, r.Namespace, r.Rules, false)
	}
	for _, r := range inv.ClusterRoles {
		eval(r.Name, "", r.Rules, true)
	}
	return out
}

func ruleRBAC002ClusterAdmin(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, crb := range inv.ClusterRoleBindings {
		if crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, s := range crb.Subjects {
			if isSystemSubject(s.Name) {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevCritical,
				Title:          "Subject bound to cluster-admin",
				Description:    fmt.Sprintf("Subject %s/%s (%s) is bound to cluster-admin via ClusterRoleBinding %q.", s.Kind, s.Namespace, s.Name, crb.Name),
				Resource:       scanner.Resource{Kind: "ClusterRoleBinding", Name: crb.Name},
				Evidence:       fmt.Sprintf("ClusterRoleBinding %s -> ClusterRole/cluster-admin (subject=%s/%s %s)", crb.Name, s.Kind, s.Namespace, s.Name),
				Impact:         "Any compromise of this identity is a total cluster takeover.",
				Recommendation: fmt.Sprintf("Replace cluster-admin with a role that lists the specific verbs/resources this subject needs. Remove %s if unused.", crb.Name),
				RemediationCmd: fmt.Sprintf("kubectl delete clusterrolebinding %s", crb.Name),
				Tags:           []string{"rbac", "cluster-admin"},
			})
		}
	}
	return out
}

func ruleRBAC003Impersonate(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	eval := func(kind, name, ns string, rules []rbacv1.PolicyRule) {
		for _, r := range rules {
			if !sliceHasAny(r.Verbs, "impersonate", "*") {
				continue
			}
			if !sliceHasAny(r.Resources, "users", "groups", "serviceaccounts", "uids", "*") {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          "Role grants impersonate verb",
				Description:    fmt.Sprintf("%s %q can impersonate identities.", kind, name),
				Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
				Evidence:       fmt.Sprintf("verbs=%v resources=%v", r.Verbs, r.Resources),
				Impact:         "Subject can act as any user/group/SA → privilege escalation to cluster-admin if target exists.",
				Recommendation: "Remove impersonate. If genuinely needed, scope with resourceNames to specific identities.",
				References:     []string{"MITRE T1078"},
				MitreATTACK:    []string{"T1078"},
				Tags:           []string{"rbac", "privesc"},
			})
			break
		}
	}
	for _, r := range inv.Roles {
		eval("Role", r.Name, r.Namespace, r.Rules)
	}
	for _, r := range inv.ClusterRoles {
		eval("ClusterRole", r.Name, "", r.Rules)
	}
	return out
}

func ruleRBAC004BindEscalate(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	eval := func(kind, name, ns string, rules []rbacv1.PolicyRule) {

		if isSystemRole(name) {
			return
		}
		for _, r := range rules {
			if !sliceHasAny(r.APIGroups, "rbac.authorization.k8s.io", "*") {
				continue
			}
			hasVerb := sliceHasAny(r.Verbs, "bind", "escalate", "*")
			hasRes := sliceHasAny(r.Resources, "roles", "clusterroles", "rolebindings", "clusterrolebindings", "*")
			if hasVerb && hasRes {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevCritical,
					Title:          "Role grants bind/escalate on RBAC objects",
					Description:    fmt.Sprintf("%s %q has bind or escalate verbs on roles/clusterroles. This is a direct privilege-escalation primitive.", kind, name),
					Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
					Evidence:       fmt.Sprintf("verbs=%v resources=%v", r.Verbs, r.Resources),
					Impact:         "Holder can create bindings to any role including cluster-admin and escalate their own permissions.",
					Recommendation: "Drop bind/escalate. If RBAC changes are required, automate via CI with an admin identity, not in-cluster.",
					Tags:           []string{"rbac", "privesc", "critical"},
				})
				return
			}
		}
	}
	for _, r := range inv.Roles {
		eval("Role", r.Name, r.Namespace, r.Rules)
	}
	for _, r := range inv.ClusterRoles {
		eval("ClusterRole", r.Name, "", r.Rules)
	}
	return out
}

func ruleRBAC005SecretAccess(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	eval := func(kind, name, ns string, rules []rbacv1.PolicyRule) {
		if isSystemRole(name) {
			return
		}
		for _, r := range rules {
			if !sliceHasAny(r.Resources, "secrets", "*") {
				continue
			}
			if !sliceHasAny(r.Verbs, "get", "list", "watch", "*") {
				continue
			}
			if len(r.ResourceNames) > 0 {
				continue
			}
			sev := scanner.SevHigh
			if sliceHas(r.Verbs, "*") {
				sev = scanner.SevCritical
			}
			out = append(out, scanner.Finding{
				Severity:       sev,
				Title:          "Role grants broad read access to Secrets",
				Description:    fmt.Sprintf("%s %q can read any Secret in its scope.", kind, name),
				Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
				Evidence:       fmt.Sprintf("verbs=%v resources=%v", r.Verbs, r.Resources),
				Impact:         "Secrets hold service account tokens, cloud credentials and application passwords. Leaking them typically results in full cluster or cloud compromise.",
				Recommendation: "Restrict with resourceNames, split read into specific Secret names, or store sensitive material in an external vault accessed via ESO / CSI.",
				Tags:           []string{"rbac", "secret-access"},
			})
			return
		}
	}
	for _, r := range inv.Roles {
		eval("Role", r.Name, r.Namespace, r.Rules)
	}
	for _, r := range inv.ClusterRoles {
		eval("ClusterRole", r.Name, "", r.Rules)
	}
	return out
}

func ruleRBAC006PodExec(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	eval := func(kind, name, ns string, rules []rbacv1.PolicyRule) {
		if isSystemRole(name) {
			return
		}
		for _, r := range rules {
			resHit := false
			for _, res := range r.Resources {
				switch res {
				case "pods/exec", "pods/attach", "pods/portforward", "*":
					resHit = true
				}
			}
			if !resHit {
				continue
			}
			if !sliceHasAny(r.Verbs, "create", "*") {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          "Role grants pod exec/attach/port-forward",
				Description:    fmt.Sprintf("%s %q allows shell access into pods.", kind, name),
				Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
				Evidence:       fmt.Sprintf("verbs=%v resources=%v", r.Verbs, r.Resources),
				Impact:         "Holder can execute arbitrary commands inside any pod, steal SA tokens mounted there, and pivot further.",
				Recommendation: "Restrict with resourceNames to specific pod names, or remove entirely. Use audit logs to detect exec usage.",
				Tags:           []string{"rbac", "pod-exec"},
			})
			return
		}
	}
	for _, r := range inv.Roles {
		eval("Role", r.Name, r.Namespace, r.Rules)
	}
	for _, r := range inv.ClusterRoles {
		eval("ClusterRole", r.Name, "", r.Rules)
	}
	return out
}

func ruleRBAC007PodCreate(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	eval := func(kind, name, ns string, rules []rbacv1.PolicyRule) {
		for _, r := range rules {
			canCreate, canMutate := false, false
			for _, target := range []struct{ group, resource string }{
				{"", "pods"}, {"apps", "deployments"}, {"apps", "daemonsets"},
				{"apps", "statefulsets"}, {"apps", "replicasets"},
				{"batch", "jobs"}, {"batch", "cronjobs"},
			} {
				match := func(verb string) bool {
					return rbacutil.Matches(r.APIGroups, r.Resources, r.Verbs, nil, target.group, target.resource, "", verb, "")
				}
				canCreate = canCreate || (len(r.ResourceNames) == 0 && match("create"))
				canMutate = canMutate || match("patch") || match("update")
			}
			if !canCreate && !canMutate {
				continue
			}
			title := "Role can mutate existing workloads"
			impact := "Holder may replace container images or alter mutable controller templates. Updating existing pods cannot change immutable privileged, hostPath, host-namespace or service-account settings."
			if canCreate {
				title = "Role can create workloads; dangerous admission is unverified"
				impact = "Holder can create workloads even in an empty namespace. Privileged pods, hostPath, other service accounts and control-plane placement depend on admission and runtime constraints, not RBAC alone."
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          title,
				Description:    fmt.Sprintf("%s %q can create or mutate pods/workloads.", kind, name),
				Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
				Evidence:       fmt.Sprintf("verbs=%v resources=%v", r.Verbs, r.Resources),
				Impact:         impact,
				Recommendation: "Gate pod-create with Pod Security Admission (restricted profile) and admission policies that forbid privileged/hostPath/hostNetwork. Use a policy engine (Kyverno/OPA Gatekeeper).",
				Tags:           []string{"rbac", "pod-create"},
			})
			return
		}
	}
	for _, r := range inv.Roles {
		eval("Role", r.Name, r.Namespace, r.Rules)
	}
	for _, r := range inv.ClusterRoles {
		if !isSystemRole(r.Name) {
			eval("ClusterRole", r.Name, "", r.Rules)
			continue
		}

		for _, binding := range inv.RoleBindings {
			if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == r.Name {
				eval("RoleBinding", binding.Name, binding.Namespace, r.Rules)
			}
		}
		for _, binding := range inv.ClusterRoleBindings {
			if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == r.Name {
				eval("ClusterRoleBinding", binding.Name, "", r.Rules)
			}
		}
	}
	return out
}

func ruleRBAC008Anonymous(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, crb := range inv.ClusterRoleBindings {
		for _, s := range crb.Subjects {
			name := s.Name
			if s.Kind == "Group" && (name == "system:anonymous" || name == "system:unauthenticated") {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevCritical,
					Title:          "Anonymous group bound to cluster role",
					Description:    fmt.Sprintf("ClusterRoleBinding %q grants ClusterRole %q to %q.", crb.Name, crb.RoleRef.Name, name),
					Resource:       scanner.Resource{Kind: "ClusterRoleBinding", Name: crb.Name},
					Evidence:       fmt.Sprintf("binding=%s role=%s subject=%s", crb.Name, crb.RoleRef.Name, name),
					Impact:         "Any unauthenticated request (no token, no cert) has these permissions. If the role is privileged this is remote-unauth-RCE on the cluster.",
					Recommendation: fmt.Sprintf("Delete %q and disable anonymous auth on kube-apiserver (--anonymous-auth=false).", crb.Name),
					RemediationCmd: fmt.Sprintf("kubectl delete clusterrolebinding %s", crb.Name),
					Tags:           []string{"rbac", "anonymous", "critical"},
				})
			}
			if s.Kind == "User" && name == "system:anonymous" {
				out = append(out, scanner.Finding{
					Severity:    scanner.SevCritical,
					Title:       "User system:anonymous bound to cluster role",
					Description: fmt.Sprintf("ClusterRoleBinding %q grants ClusterRole %q to user system:anonymous.", crb.Name, crb.RoleRef.Name),
					Resource:    scanner.Resource{Kind: "ClusterRoleBinding", Name: crb.Name},
					Tags:        []string{"rbac", "anonymous", "critical"},
				})
			}
		}
	}
	return out
}

func ruleRBAC009Authenticated(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	builtins := map[string]bool{
		"system:discovery":                        true,
		"system:basic-user":                       true,
		"system:public-info-viewer":               true,
		"system:service-account-issuer-discovery": true,
	}
	for _, crb := range inv.ClusterRoleBindings {
		for _, s := range crb.Subjects {
			if s.Kind != "Group" || s.Name != "system:authenticated" {
				continue
			}
			if builtins[crb.RoleRef.Name] {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          "system:authenticated bound to non-default role",
				Description:    fmt.Sprintf("ClusterRoleBinding %q grants %q to every authenticated user.", crb.Name, crb.RoleRef.Name),
				Resource:       scanner.Resource{Kind: "ClusterRoleBinding", Name: crb.Name},
				Evidence:       fmt.Sprintf("binding=%s role=%s", crb.Name, crb.RoleRef.Name),
				Impact:         "Any valid token, including expired-looking but still valid SA tokens, low-privilege users, or CI robots, obtains these privileges.",
				Recommendation: "Scope bindings to specific users/SAs instead of system:authenticated.",
				Tags:           []string{"rbac", "over-exposure"},
			})
		}
	}
	return out
}

func ruleRBAC010DefaultSA(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	check := func(bindingName, bindingNS, roleKind, roleName string, subjects []rbacv1.Subject) {
		for _, s := range subjects {
			if s.Kind != "ServiceAccount" || s.Name != "default" {
				continue
			}
			if roleName == "system:discovery" || roleName == "system:basic-user" {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          "Default ServiceAccount bound to extra role",
				Description:    fmt.Sprintf("Default SA in namespace %q is bound to %s %q via %q.", s.Namespace, roleKind, roleName, bindingName),
				Resource:       scanner.Resource{Kind: roleKind, Namespace: bindingNS, Name: bindingName},
				Impact:         "Any pod that does not explicitly set its SA inherits these permissions.",
				Recommendation: "Create a purpose-built SA for each workload; do not grant anything to the default SA.",
				Tags:           []string{"rbac", "default-sa"},
			})
		}
	}
	for _, rb := range inv.RoleBindings {
		check(rb.Name, rb.Namespace, rb.RoleRef.Kind, rb.RoleRef.Name, rb.Subjects)
	}
	for _, crb := range inv.ClusterRoleBindings {
		check(crb.Name, "", crb.RoleRef.Kind, crb.RoleRef.Name, crb.Subjects)
	}
	return out
}

func ruleRBAC011Orphaned(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	saSet := map[string]bool{}
	for _, sa := range inv.ServiceAccounts {
		saSet[sa.Namespace+"/"+sa.Name] = true
	}
	check := func(kind, name, ns string, s rbacv1.Subject) {
		if s.Kind != "ServiceAccount" {
			return
		}
		if !saSet[s.Namespace+"/"+s.Name] {
			out = append(out, scanner.Finding{
				Severity:       scanner.SevLow,
				Title:          "Orphaned RBAC binding — subject SA does not exist",
				Description:    fmt.Sprintf("%s %q references non-existent ServiceAccount %s/%s.", kind, name, s.Namespace, s.Name),
				Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
				Recommendation: "Delete the stale binding. Orphan bindings are a marker of dead code paths and hinder auditing.",
				Tags:           []string{"rbac", "hygiene"},
			})
		}
	}
	for _, rb := range inv.RoleBindings {
		for _, s := range rb.Subjects {
			check("RoleBinding", rb.Name, rb.Namespace, s)
		}
	}
	for _, crb := range inv.ClusterRoleBindings {
		for _, s := range crb.Subjects {
			check("ClusterRoleBinding", crb.Name, "", s)
		}
	}
	return out
}

func ruleRBAC012CSRApprove(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	eval := func(kind, name, ns string, rules []rbacv1.PolicyRule) {
		for _, r := range rules {
			if !sliceHasAny(r.APIGroups, "certificates.k8s.io", "*") {
				continue
			}
			if !sliceHasAny(r.Resources, "certificatesigningrequests/approval", "signers", "*") {
				continue
			}
			if !sliceHasAny(r.Verbs, "approve", "sign", "update", "*") {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          "Role can approve/sign certificate signing requests",
				Description:    fmt.Sprintf("%s %q has rights to approve or sign CSRs.", kind, name),
				Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
				Evidence:       fmt.Sprintf("verbs=%v resources=%v", r.Verbs, r.Resources),
				Impact:         "Holder can mint a client certificate for any user/group, including system:masters → cluster-admin.",
				Recommendation: "Restrict to specific signer names via resourceNames, or keep this permission exclusive to the CSR approving controller.",
				Tags:           []string{"rbac", "privesc"},
			})
			return
		}
	}
	for _, r := range inv.Roles {
		eval("Role", r.Name, r.Namespace, r.Rules)
	}
	for _, r := range inv.ClusterRoles {
		eval("ClusterRole", r.Name, "", r.Rules)
	}
	return out
}

func ruleRBAC013NodesProxy(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	eval := func(kind, name, ns string, rules []rbacv1.PolicyRule) {
		if isSystemRole(name) {
			return
		}
		for _, r := range rules {
			if !sliceHasAny(r.Resources, "nodes/proxy", "nodes/exec", "*") {
				continue
			}
			if !sliceHasAny(r.Verbs, "get", "create", "update", "*") {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevCritical,
				Title:          "Role grants nodes/proxy or nodes/exec",
				Description:    fmt.Sprintf("%s %q can proxy to kubelet API or exec via node subresource.", kind, name),
				Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
				Impact:         "Direct command execution on every node (kubelet /exec, /run endpoints).",
				Recommendation: "Remove nodes/proxy and nodes/exec permissions. The kubelet API is not intended as a user-facing surface.",
				Tags:           []string{"rbac", "kubelet"},
			})
			return
		}
	}
	for _, r := range inv.Roles {
		eval("Role", r.Name, r.Namespace, r.Rules)
	}
	for _, r := range inv.ClusterRoles {
		eval("ClusterRole", r.Name, "", r.Rules)
	}
	return out
}

func sliceHas(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func sliceHasAny(ss []string, wants ...string) bool {
	for _, w := range wants {
		for _, s := range ss {
			if strings.EqualFold(s, w) {
				return true
			}
		}
	}
	return false
}

func isSystemRole(name string) bool {
	if name == "cluster-admin" || name == "admin" || name == "edit" || name == "view" {
		return true
	}
	return strings.HasPrefix(name, "system:")
}

func isSystemSubject(name string) bool {
	return strings.HasPrefix(name, "system:") ||
		name == "masters" ||
		strings.HasPrefix(name, "kubeadm:")
}
