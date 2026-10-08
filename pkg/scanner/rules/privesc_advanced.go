package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func AdvancedPrivescRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-RBAC-014", Title: "Ephemeral container injection permission requires admission review", Category: scanner.CatRBAC, Fn: ruleRBAC014EphemeralContainers},
		{ID: "KH-RBAC-015", Title: "Port-forward enables lateral movement past NetworkPolicy", Category: scanner.CatRBAC, Fn: ruleRBAC015PortForward},
		{ID: "KH-RBAC-016", Title: "Secret create + get can mint SA tokens", Category: scanner.CatRBAC, Fn: ruleRBAC016SecretMint},
		{ID: "KH-RBAC-017", Title: "Pod delete + node manipulation enables pod migration attack", Category: scanner.CatRBAC, Fn: ruleRBAC017PodDeleteNode},
		{ID: "KH-RBAC-018", Title: "Workload controller modification can create privileged pods", Category: scanner.CatRBAC, Fn: ruleRBAC018WorkloadController},
		{ID: "KH-RBAC-019", Title: "ServiceAccount token creation (TokenRequest abuse)", Category: scanner.CatRBAC, Fn: ruleRBAC019SATokenCreate},
	}
}

func AdvancedWorkloadRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-WRK-016", Title: "Containerd socket mounted", Category: scanner.CatWorkload, Fn: ruleWRK016ContainerdSock},
		{ID: "KH-WRK-017", Title: "PV-backed hostPath bypass (PSA invisible)", Category: scanner.CatWorkload, Fn: ruleWRK017PVHostPath},
		{ID: "KH-WRK-018", Title: "Container requests Unmasked /proc", Category: scanner.CatWorkload, Fn: ruleWRK018ProcMountUnmasked},
		{ID: "KH-WRK-019", Title: "Lifecycle exec hook (persistence risk)", Category: scanner.CatWorkload, Fn: ruleWRK019LifecycleHook},
		{ID: "KH-WRK-020", Title: "Image not digest-pinned with Always pull policy", Category: scanner.CatWorkload, Fn: ruleWRK020NoDigestPin},
		{ID: "KH-WRK-021", Title: "Container missing liveness and readiness probes", Category: scanner.CatWorkload, Fn: ruleWRK021MissingProbes},
		{ID: "KH-WRK-022", Title: "Namespace runs PSA violators without enforce label", Category: scanner.CatWorkload, Fn: ruleWRK022PSALabels},
	}
}

func AdvancedSecretRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-SEC-010", Title: "ConfigMap contains high-confidence credential key", Category: scanner.CatSecret, Fn: ruleSEC010ConfigMapCreds},
		{ID: "KH-SEC-011", Title: "Cross-namespace secret access via RBAC", Category: scanner.CatSecret, Fn: ruleSEC011CrossNSSecret},
		{ID: "KH-SEC-012", Title: "TLS secret expired or expiring soon", Category: scanner.CatSecret, Fn: ruleSEC012TLSExpiry},
		{ID: "KH-SEC-013", Title: "Secret unreferenced by any workload", Category: scanner.CatSecret, Fn: ruleSEC013StaleSecret},
	}
}

func AdvancedNetworkRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-NET-005", Title: "NetworkPolicy bridges a sensitive namespace", Category: scanner.CatNetwork, Fn: ruleNET005CrossNS},
		{ID: "KH-NET-006", Title: "Workload not selected by any NetworkPolicy", Category: scanner.CatNetwork, Fn: ruleNET006Unselected},
	}
}

func AdvancedSARules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-SA-003", Title: "DaemonSet SA blast radius (token on every node)", Category: scanner.CatWorkload, Fn: ruleSA003DaemonSetSA},
	}
}

func ruleRBAC014EphemeralContainers(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, r := range append(rolesToGeneric(inv.Roles, false), rolesToGeneric(inv.ClusterRoles, true)...) {
		for _, rule := range r.rules {
			if !hasSubresource(rule, "pods", "ephemeralcontainers") {
				continue
			}
			if !sliceHasAny(rule.Verbs, "update", "patch", "*") {
				continue
			}
			if isSystemRoleAdv(r.name) {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          fmt.Sprintf("%s %q grants pods/ephemeralcontainers update/patch", r.kind, r.name),
				Description:    "This role grants ephemeral debug-container mutation within its binding scope and resourceNames restrictions. It does not prove the current identity holds the role, that a running target exists, or that admission accepts a privileged container. Pod-level security settings still apply, while container-specific settings and mounts require separate review. Exec/attach and runtime process sharing are additional conditions; no injection or host access was performed.",
				Resource:       scanner.Resource{Kind: r.kind, Namespace: r.ns, Name: r.name},
				Evidence:       fmt.Sprintf("verbs=%v resourceNames=%v on pods/ephemeralcontainers; admission and runtime unverified", rule.Verbs, rule.ResourceNames),
				Impact:         "Potential debug-container code execution if the bound identity, target and admission conditions permit it. Privileged/root behavior, token mounts and host access are not implied by the permission alone.",
				Recommendation: "Remove pods/ephemeralcontainers update/patch from non-admin identities. Use kubectl debug with RBAC-gated profiles.",
				References:     []string{"https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/"},
				MitreATTACK:    []string{"T1611"},
				Tags:           []string{"rbac", "privesc", "ephemeral-containers"},
			})
		}
	}
	return out
}

func ruleRBAC015PortForward(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, r := range append(rolesToGeneric(inv.Roles, false), rolesToGeneric(inv.ClusterRoles, true)...) {
		for _, rule := range r.rules {
			if !hasSubresource(rule, "pods", "portforward") {
				continue
			}
			if !sliceHasAny(rule.Verbs, "create", "*") {
				continue
			}
			if isSystemRoleAdv(r.name) {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevMedium,
				Title:          fmt.Sprintf("%s %q grants pods/portforward create", r.kind, r.name),
				Description:    "Port-forward tunnels bypass NetworkPolicy entirely, enabling direct TCP access to internal-only services (databases, dashboards, Redis, etc.) from any pod the subject can target.",
				Resource:       scanner.Resource{Kind: r.kind, Namespace: r.ns, Name: r.name},
				Evidence:       fmt.Sprintf("verbs=%v on pods/portforward", rule.Verbs),
				Impact:         "Lateral movement past NetworkPolicy to internal databases, dashboards, and services.",
				Recommendation: "Remove pods/portforward from application identities. Reserve for break-glass debugging.",
				Tags:           []string{"rbac", "lateral-movement", "portforward"},
			})
		}
	}
	return out
}

func ruleRBAC016SecretMint(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	type roleInfo struct {
		name, ns, kind string
		canCreate      bool
		canGet         bool
	}
	roles := append(rolesToGeneric(inv.Roles, false), rolesToGeneric(inv.ClusterRoles, true)...)
	for _, r := range roles {
		if isSystemRoleAdv(r.name) {
			continue
		}
		canCreate, canGet := false, false
		for _, rule := range r.rules {
			if !sliceHasAny(rule.Resources, "secrets", "*") {
				continue
			}
			if sliceHasAny(rule.Verbs, "create", "*") {
				canCreate = true
			}
			if sliceHasAny(rule.Verbs, "get", "*") {
				canGet = true
			}
		}
		if canCreate && canGet {
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          fmt.Sprintf("%s %q can create AND get secrets (token mint)", r.kind, r.name),
				Description:    "A subject with both create and get on secrets can mint a legacy token Secret pointed at a privileged ServiceAccount, then read the controller-populated token field. This bypasses TokenRequest audience/expiry controls.",
				Resource:       scanner.Resource{Kind: r.kind, Namespace: r.ns, Name: r.name},
				Evidence:       "secrets: create + get held in same scope",
				Impact:         "Impersonate any ServiceAccount in scope by minting a legacy token Secret.",
				Recommendation: "Split create and get on secrets across different subjects. Prefer the TokenRequest API over legacy token Secrets.",
				References:     []string{"https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#manual-secret-management-for-serviceaccounts"},
				MitreATTACK:    []string{"T1528"},
				Tags:           []string{"rbac", "privesc", "token-mint"},
			})
		}
	}
	return out
}

func ruleRBAC017PodDeleteNode(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, r := range rolesToGeneric(inv.ClusterRoles, true) {
		if isSystemRoleAdv(r.name) {
			continue
		}
		canDeletePods, canManipulateNodes := false, false
		for _, rule := range r.rules {
			if sliceHasAny(rule.Resources, "pods", "*") && sliceHasAny(rule.Verbs, "delete", "*") {
				canDeletePods = true
			}
			if sliceHasAny(rule.Resources, "nodes", "nodes/status", "*") && sliceHasAny(rule.Verbs, "update", "patch", "delete", "*") {
				canManipulateNodes = true
			}
		}
		if canDeletePods && canManipulateNodes {
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          fmt.Sprintf("ClusterRole %q can delete pods + manipulate nodes", r.name),
				Description:    "A subject that can delete pods AND cordon/taint/delete nodes can evict a sensitive pod and force it to reschedule onto an attacker-controlled node, capturing its SA token and secrets.",
				Resource:       scanner.Resource{Kind: "ClusterRole", Name: r.name},
				Evidence:       "pods: delete AND nodes/nodes/status: update/patch/delete",
				Impact:         "Force pod migration to attacker node. Steal ServiceAccount tokens and mounted secrets.",
				Recommendation: "Separate node-lifecycle automation from workload identities. Use PodDisruptionBudgets.",
				MitreATTACK:    []string{"T1078"},
				Tags:           []string{"rbac", "privesc", "node-manipulation"},
			})
		}
	}
	return out
}

func ruleRBAC018WorkloadController(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	controllers := []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "replicasets"}
	var out []scanner.Finding
	for _, r := range append(rolesToGeneric(inv.Roles, false), rolesToGeneric(inv.ClusterRoles, true)...) {
		if isSystemRoleAdv(r.name) {
			continue
		}
		for _, rule := range r.rules {
			if !sliceHasAny(rule.Verbs, "create", "update", "patch", "*") {
				continue
			}
			for _, ctrl := range controllers {
				if sliceHasAny(rule.Resources, ctrl, "*") {
					out = append(out, scanner.Finding{
						Severity:       scanner.SevHigh,
						Title:          fmt.Sprintf("%s %q can create/patch %s (indirect pod creation)", r.kind, r.name, ctrl),
						Description:    fmt.Sprintf("Modifying a %s allows specifying arbitrary pod templates with privileged securityContexts, hostPath mounts, or SA token access, bypassing direct pod-create restrictions.", ctrl),
						Resource:       scanner.Resource{Kind: r.kind, Namespace: r.ns, Name: r.name},
						Evidence:       fmt.Sprintf("verbs=%v on %s", rule.Verbs, ctrl),
						Impact:         "Indirect privilege escalation via workload controller modification.",
						Recommendation: "Route deployments through controlled automation (CI/CD). Remove direct controller modification from runtime identities.",
						MitreATTACK:    []string{"T1078"},
						Tags:           []string{"rbac", "privesc", "workload-controller"},
					})
					break
				}
			}
		}
	}
	return out
}

func ruleRBAC019SATokenCreate(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, r := range append(rolesToGeneric(inv.Roles, false), rolesToGeneric(inv.ClusterRoles, true)...) {
		for _, rule := range r.rules {
			if !hasSubresource(rule, "serviceaccounts", "token") {
				continue
			}
			if !sliceHasAny(rule.Verbs, "create", "*") {
				continue
			}
			if isSystemRoleAdv(r.name) {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          fmt.Sprintf("%s %q grants serviceaccounts/token create", r.kind, r.name),
				Description:    "The TokenRequest API can mint short-lived tokens for any ServiceAccount in scope. An attacker with this permission can impersonate privileged SAs without needing secret access.",
				Resource:       scanner.Resource{Kind: r.kind, Namespace: r.ns, Name: r.name},
				Evidence:       fmt.Sprintf("verbs=%v on serviceaccounts/token", rule.Verbs),
				Impact:         "Impersonate any ServiceAccount in scope. Steal cluster-admin if a privileged SA exists.",
				Recommendation: "Limit serviceaccounts/token create to trusted control-plane components.",
				References:     []string{"https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/"},
				MitreATTACK:    []string{"T1528"},
				Tags:           []string{"rbac", "privesc", "token-request"},
			})
		}
	}
	return out
}

func ruleWRK016ContainerdSock(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			path := v.HostPath.Path
			if path == "/var/run/containerd/containerd.sock" || path == "/run/containerd/containerd.sock" {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevCritical,
					Title:          "Containerd socket mounted into pod",
					Description:    fmt.Sprintf("Pod %s/%s mounts the containerd socket (%s). This gives the pod full control over the container runtime, equivalent to node-root.", p.Namespace, p.Name, path),
					Resource:       podResource(p),
					Evidence:       fmt.Sprintf("hostPath.path=%s", path),
					Impact:         "Full container runtime control. Can create privileged containers, escape to host, read all container filesystems.",
					Recommendation: "Remove the containerd socket mount. Use CSI or dedicated sidecars for image operations.",
					References:     []string{"CIS 5.2.1"},
					MitreATTACK:    []string{"T1611"},
					Tags:           []string{"container-escape", "containerd-socket"},
				})
			}
		}
	}
	return out
}

func ruleWRK017PVHostPath(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	sensitivePaths := []string{"/", "/etc", "/proc", "/sys", "/var/run/docker.sock",
		"/var/run/containerd/containerd.sock", "/var/lib/kubelet", "/var/log",
		"/root", "/home", "/var/lib/rancher"}

	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			path := v.HostPath.Path
			for _, sp := range sensitivePaths {
				if path == sp || (sp != "/" && strings.HasPrefix(path, sp+"/")) {

					if sp == "/var/lib/kubelet" || sp == "/var/lib/rancher" || sp == "/root" || sp == "/home" {
						out = append(out, scanner.Finding{
							Severity:       scanner.SevHigh,
							Title:          fmt.Sprintf("Sensitive hostPath %q mounted (credential exposure)", path),
							Description:    fmt.Sprintf("Pod %s/%s mounts hostPath %q which may contain kubelet credentials, kubeconfig files, or user SSH keys.", p.Namespace, p.Name, path),
							Resource:       podResource(p),
							Evidence:       fmt.Sprintf("hostPath.path=%s", path),
							Impact:         "Access to kubelet credentials, kubeconfig, or user keys enables lateral movement and privilege escalation.",
							Recommendation: "Replace with scoped ConfigMaps/Secrets/CSI volumes. Block hostPath via Pod Security Admission.",
							MitreATTACK:    []string{"T1552", "T1006"},
							Tags:           []string{"hostpath", "credential-exposure"},
						})
					}
					break
				}
			}
		}
	}
	return out
}

func ruleWRK018ProcMountUnmasked(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			if c.SecurityContext == nil {
				continue
			}
			if c.SecurityContext.ProcMount != nil && string(*c.SecurityContext.ProcMount) == "Unmasked" {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevHigh,
					Title:          fmt.Sprintf("Container %q requests Unmasked /proc", c.Name),
					Description:    fmt.Sprintf("Container %q in pod %s/%s sets procMount=Unmasked, exposing the full /proc filesystem without masking sensitive paths like /proc/kcore, /proc/sched_debug, etc.", c.Name, p.Namespace, p.Name),
					Resource:       podResource(p),
					Evidence:       "securityContext.procMount=Unmasked",
					Impact:         "Access to sensitive kernel information. May enable container escape via /proc/sys writes.",
					Recommendation: "Remove procMount field (default 'Default' is safe). Enforce PSA baseline profile.",
					References:     []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
					MitreATTACK:    []string{"T1611"},
					Tags:           []string{"proc-mount", "container-escape"},
				})
			}
		}
	}
	return out
}

func ruleWRK019LifecycleHook(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			if c.Lifecycle == nil {
				continue
			}
			checkHook := func(hook *corev1.LifecycleHandler, phase string) {
				if hook == nil || hook.Exec == nil {
					return
				}
				cmd := strings.Join(hook.Exec.Command, " ")
				if cmd == "" || cmd == "sleep 1" || cmd == "sleep 5" {
					return
				}
				out = append(out, scanner.Finding{
					Severity:       scanner.SevMedium,
					Title:          fmt.Sprintf("Container %q has %s exec hook", c.Name, phase),
					Description:    fmt.Sprintf("Container %q in pod %s/%s declares a lifecycle.%s.exec command. Inline exec hooks can be used for persistence (backdoor scripts, reverse shells) and are harder to audit than image entrypoints.", c.Name, p.Namespace, p.Name, phase),
					Resource:       podResource(p),
					Evidence:       fmt.Sprintf("lifecycle.%s.exec.command=%s", phase, cmd),
					Impact:         "Persistence mechanism. Code runs on every pod start/stop outside normal container image.",
					Recommendation: "Move logic into the container image or an init container. Replace inline sh -c with auditable scripts.",
					Tags:           []string{"lifecycle-hook", "persistence"},
				})
			}
			checkHook(c.Lifecycle.PostStart, "postStart")
			checkHook(c.Lifecycle.PreStop, "preStop")
		}
	}
	return out
}

func ruleWRK020NoDigestPin(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			if strings.Contains(c.Image, "@sha256:") {
				continue
			}
			policy := corev1.PullIfNotPresent
			if c.ImagePullPolicy != "" {
				policy = c.ImagePullPolicy
			} else if strings.HasSuffix(c.Image, ":latest") || !strings.Contains(c.Image, ":") {
				policy = corev1.PullAlways
			}
			if policy != corev1.PullAlways {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevMedium,
				Title:          fmt.Sprintf("Image %q not digest-pinned with Always pull", c.Image),
				Description:    fmt.Sprintf("Container %q in pod %s/%s uses image %q without a sha256 digest and pulls Always. A compromised registry or tag overwrite delivers malicious code silently.", c.Name, p.Namespace, p.Name, c.Image),
				Resource:       podResource(p),
				Evidence:       fmt.Sprintf("image=%s imagePullPolicy=%s (no @sha256:)", c.Image, policy),
				Impact:         "Supply-chain attack via tag mutation. Attacker replaces image contents without changing the reference.",
				Recommendation: "Pin images to digest: registry/app@sha256:<digest>. Sign and verify with cosign/Sigstore.",
				Tags:           []string{"supply-chain", "image-pinning"},
			})
		}
	}
	return out
}

func ruleWRK021MissingProbes(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		if p.Namespace == "kube-system" || p.Namespace == "kube-public" {
			continue
		}
		for _, c := range p.Spec.Containers {
			if c.LivenessProbe == nil && c.ReadinessProbe == nil {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevLow,
					Title:          fmt.Sprintf("Container %q has no liveness or readiness probe", c.Name),
					Description:    fmt.Sprintf("Container %q in pod %s/%s declares neither a liveness nor readiness probe. Without probes, Kubernetes cannot detect application failures or startup delays.", c.Name, p.Namespace, p.Name),
					Resource:       podResource(p),
					Evidence:       "livenessProbe=nil readinessProbe=nil",
					Impact:         "Undetected application failures. Dead containers continue receiving traffic.",
					Recommendation: "Add a readiness probe gated on real dependencies and a liveness probe. Tune initialDelaySeconds appropriately.",
					Tags:           []string{"reliability", "probes"},
				})
			}
		}
	}
	return out
}

func ruleWRK022PSALabels(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, ns := range inv.Namespaces {
		if systemNamespaces[ns.Name] {
			continue
		}
		enforceLabel := ns.Labels["pod-security.kubernetes.io/enforce"]
		if enforceLabel == "baseline" || enforceLabel == "restricted" {
			continue
		}

		hasViolator := false
		for _, p := range inv.Pods {
			if p.Namespace != ns.Name {
				continue
			}
			if isPSAViolator(p) {
				hasViolator = true
				break
			}
		}
		if !hasViolator {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("Namespace %q runs PSA violators without enforce label", ns.Name),
			Description:    fmt.Sprintf("Namespace %q has pods with privileged/hostNetwork/hostPID/hostPath specs but no pod-security.kubernetes.io/enforce label at baseline or restricted level. PSA is not blocking dangerous pod specs.", ns.Name),
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns.Name},
			Evidence:       fmt.Sprintf("enforce=%q (need baseline or restricted)", enforceLabel),
			Impact:         "No admission control prevents privileged pod creation in this namespace.",
			Recommendation: "Apply pod-security.kubernetes.io/enforce=baseline (or restricted) label to the namespace.",
			RemediationCmd: fmt.Sprintf("kubectl label ns %s pod-security.kubernetes.io/enforce=baseline --overwrite", ns.Name),
			Tags:           []string{"psa", "admission", "namespace"},
		})
	}
	return out
}

var highConfidenceCredKeys = []string{
	"password", "passwd", "secret", "api_key", "apikey", "api-key",
	"aws_secret_access_key", "aws_access_key_id", "dsn", "connection_string",
	"client_secret", "private_key", "access_key", "secret_key",
	"database_url", "db_password", "redis_password", "smtp_password",
}

func ruleSEC010ConfigMapCreds(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, cm := range inv.ConfigMaps {
		if cm.Namespace == "kube-system" || cm.Namespace == "kube-public" {
			continue
		}
		for key := range cm.Data {
			keyLower := strings.ToLower(key)
			for _, pattern := range highConfidenceCredKeys {
				if keyLower == pattern || strings.Contains(keyLower, pattern) {
					out = append(out, scanner.Finding{
						Severity:       scanner.SevHigh,
						Title:          fmt.Sprintf("ConfigMap %s/%s has credential-like key %q", cm.Namespace, cm.Name, key),
						Description:    fmt.Sprintf("ConfigMap %s/%s contains key %q matching a high-confidence credential pattern. ConfigMaps are not encrypted at rest and are visible to anyone with list/watch on configmaps.", cm.Namespace, cm.Name, key),
						Resource:       scanner.Resource{Kind: "ConfigMap", Namespace: cm.Namespace, Name: cm.Name},
						Evidence:       fmt.Sprintf("key=%q matches pattern=%q", key, pattern),
						Impact:         "Credential exposure. ConfigMaps are not encrypted at rest and lack access audit trails.",
						Recommendation: "Move the credential to a Secret (encrypted at rest) or an external secret store (Vault, AWS SM).",
						Tags:           []string{"credentials", "configmap", "data-exposure"},
					})
					break
				}
			}
		}
	}
	return out
}

func ruleSEC011CrossNSSecret(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding

	for _, rb := range inv.RoleBindings {
		roleName := rb.RoleRef.Name
		var rules []rbacv1.PolicyRule
		switch rb.RoleRef.Kind {
		case "Role":
			for _, role := range inv.Roles {
				if role.Name == roleName && role.Namespace == rb.Namespace {
					rules = role.Rules
					break
				}
			}
		case "ClusterRole":
			for _, role := range inv.ClusterRoles {
				if role.Name == roleName {
					rules = role.Rules
					break
				}
			}
		}
		if len(rules) == 0 {
			continue
		}
		hasSecretAccess := false
		for _, rule := range rules {
			if sliceHasAny(rule.APIGroups, "", "*") && sliceHasAny(rule.Resources, "secrets", "*") && sliceHasAny(rule.Verbs, "get", "list", "watch", "*") {
				hasSecretAccess = true
				break
			}
		}
		if !hasSecretAccess {
			continue
		}
		for _, subj := range rb.Subjects {
			if subj.Kind != "ServiceAccount" {
				continue
			}
			if subj.Namespace != "" && subj.Namespace != rb.Namespace {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevMedium,
					Title:          fmt.Sprintf("SA %s/%s can read secrets in namespace %s", subj.Namespace, subj.Name, rb.Namespace),
					Description:    fmt.Sprintf("ServiceAccount %s/%s is bound via RoleBinding %q to read secrets in namespace %q. Cross-namespace secret access widens blast radius.", subj.Namespace, subj.Name, rb.Name, rb.Namespace),
					Resource:       scanner.Resource{Kind: "RoleBinding", Namespace: rb.Namespace, Name: rb.Name},
					Evidence:       fmt.Sprintf("subject=%s/%s target_ns=%s", subj.Namespace, subj.Name, rb.Namespace),
					Impact:         "Compromise of the SA's workload exposes secrets in another namespace.",
					Recommendation: "Move the workload into the target namespace, narrow to resourceNames, or use operator selector mechanisms.",
					Tags:           []string{"cross-namespace", "secrets", "rbac"},
				})
			}
		}
	}
	return out
}

func ruleSEC012TLSExpiry(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	now := time.Now()
	thirtyDays := 30 * 24 * time.Hour
	for _, s := range inv.Secrets {
		if s.Type != corev1.SecretTypeTLS {
			continue
		}

		expiryStr := ""
		for _, key := range []string{"cert-manager.io/not-after", "notafter", "expiration"} {
			if v, ok := s.Annotations[key]; ok {
				expiryStr = v
				break
			}
		}
		if expiryStr == "" {
			continue
		}

		var expiry time.Time
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
			if t, err := time.Parse(layout, expiryStr); err == nil {
				expiry = t
				break
			}
		}
		if expiry.IsZero() {
			continue
		}
		if expiry.Before(now) {
			out = append(out, scanner.Finding{
				Severity:       scanner.SevMedium,
				Title:          fmt.Sprintf("TLS secret %s/%s has EXPIRED", s.Namespace, s.Name),
				Description:    fmt.Sprintf("TLS secret %s/%s expired on %s (%d days ago).", s.Namespace, s.Name, expiry.Format("2006-01-02"), int(now.Sub(expiry).Hours()/24)),
				Resource:       scanner.Resource{Kind: "Secret", Namespace: s.Namespace, Name: s.Name},
				Evidence:       fmt.Sprintf("expiry=%s (expired %d days ago)", expiryStr, int(now.Sub(expiry).Hours()/24)),
				Impact:         "TLS connections using this certificate will fail or show browser warnings.",
				Recommendation: "Force renewal via cert-manager (cmctl renew). Check Issuer health.",
				Tags:           []string{"tls", "certificate", "expired"},
			})
		} else if expiry.Before(now.Add(thirtyDays)) {
			daysLeft := int(expiry.Sub(now).Hours() / 24)
			out = append(out, scanner.Finding{
				Severity:       scanner.SevLow,
				Title:          fmt.Sprintf("TLS secret %s/%s expires in %d days", s.Namespace, s.Name, daysLeft),
				Description:    fmt.Sprintf("TLS secret %s/%s expires on %s (%d days from now).", s.Namespace, s.Name, expiry.Format("2006-01-02"), daysLeft),
				Resource:       scanner.Resource{Kind: "Secret", Namespace: s.Namespace, Name: s.Name},
				Evidence:       fmt.Sprintf("expiry=%s (%d days remaining)", expiryStr, daysLeft),
				Impact:         "Certificate will expire soon, causing service disruptions if not renewed.",
				Recommendation: "Verify cert-manager auto-renewal is working. Set expiry alerts.",
				Tags:           []string{"tls", "certificate", "expiring-soon"},
			})
		}
	}
	return out
}

func ruleSEC013StaleSecret(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	referenced := map[string]bool{}
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.Secret != nil {
				referenced[p.Namespace+"/"+v.Secret.SecretName] = true
			}
		}
		for _, c := range allContainers(p) {
			for _, env := range c.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					referenced[p.Namespace+"/"+env.ValueFrom.SecretKeyRef.Name] = true
				}
			}
			for _, ef := range c.EnvFrom {
				if ef.SecretRef != nil {
					referenced[p.Namespace+"/"+ef.SecretRef.Name] = true
				}
			}
		}
	}
	for _, sa := range inv.ServiceAccounts {
		for _, s := range sa.Secrets {
			referenced[sa.Namespace+"/"+s.Name] = true
		}
		for _, ips := range sa.ImagePullSecrets {
			referenced[sa.Namespace+"/"+ips.Name] = true
		}
	}

	var out []scanner.Finding
	for _, s := range inv.Secrets {
		if s.Type == corev1.SecretTypeServiceAccountToken {
			continue
		}
		if s.Namespace == "kube-system" || s.Namespace == "kube-public" {
			continue
		}
		key := s.Namespace + "/" + s.Name
		if referenced[key] {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevLow,
			Title:          fmt.Sprintf("Secret %s/%s unreferenced by any workload", s.Namespace, s.Name),
			Description:    fmt.Sprintf("Secret %s/%s (type=%s) is not referenced by any pod volume, env, envFrom, or ServiceAccount in the cluster snapshot.", s.Namespace, s.Name, s.Type),
			Resource:       scanner.Resource{Kind: "Secret", Namespace: s.Namespace, Name: s.Name},
			Evidence:       fmt.Sprintf("type=%s, not in any pod spec or SA", s.Type),
			Impact:         "Unreferenced secrets are latent attack surface. If compromised, the blast radius may not be obvious.",
			Recommendation: "Confirm no out-of-cluster consumer exists. Rotate at source, then delete.",
			Tags:           []string{"stale", "secrets", "hygiene"},
		})
	}
	return out
}

var sensitiveNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
	"default": true, "gatekeeper-system": true, "istio-system": true,
	"cert-manager": true,
}

func ruleNET005CrossNS(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, np := range inv.NetworkPolicies {

		for _, rule := range np.Spec.Ingress {
			for _, from := range rule.From {
				if from.NamespaceSelector == nil {
					continue
				}

				if len(from.NamespaceSelector.MatchLabels) == 0 && len(from.NamespaceSelector.MatchExpressions) == 0 {
					out = append(out, scanner.Finding{
						Severity:       scanner.SevMedium,
						Title:          fmt.Sprintf("NetworkPolicy %s/%s allows ingress from ALL namespaces", np.Namespace, np.Name),
						Description:    "Empty namespaceSelector matches all namespaces including sensitive ones (kube-system, default). This defeats namespace isolation.",
						Resource:       scanner.Resource{Kind: "NetworkPolicy", Namespace: np.Namespace, Name: np.Name},
						Evidence:       "ingress.from[].namespaceSelector={} (matches all)",
						Impact:         "Any pod in any namespace can reach this workload. Cross-namespace lateral movement enabled.",
						Recommendation: "Use explicit namespace labels in the selector. Apply matchLabels with specific values.",
						Tags:           []string{"network-policy", "cross-namespace"},
					})
				}
			}
		}

		for _, rule := range np.Spec.Egress {
			for _, to := range rule.To {
				if to.NamespaceSelector == nil {
					continue
				}
				if len(to.NamespaceSelector.MatchLabels) == 0 && len(to.NamespaceSelector.MatchExpressions) == 0 {
					out = append(out, scanner.Finding{
						Severity:       scanner.SevMedium,
						Title:          fmt.Sprintf("NetworkPolicy %s/%s allows egress to ALL namespaces", np.Namespace, np.Name),
						Description:    "Empty namespaceSelector in egress matches all namespaces. Pods can reach sensitive services in kube-system.",
						Resource:       scanner.Resource{Kind: "NetworkPolicy", Namespace: np.Namespace, Name: np.Name},
						Evidence:       "egress.to[].namespaceSelector={} (matches all)",
						Impact:         "Pod can reach API server, etcd, CoreDNS admin, and other sensitive services.",
						Recommendation: "Replace empty namespaceSelector with explicit matchLabels.",
						Tags:           []string{"network-policy", "cross-namespace", "egress"},
					})
				}
			}
		}
	}
	return out
}

func ruleNET006Unselected(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {

	nsWithPolicy := map[string]bool{}
	for _, np := range inv.NetworkPolicies {
		nsWithPolicy[np.Namespace] = true
	}

	var out []scanner.Finding
	for _, p := range inv.Pods {
		if !nsWithPolicy[p.Namespace] {
			continue
		}
		if p.Namespace == "kube-system" {
			continue
		}
		selected := false
		for _, np := range inv.NetworkPolicies {
			if np.Namespace != p.Namespace {
				continue
			}
			if selectorMatchesPod(np.Spec.PodSelector, p) {
				selected = true
				break
			}
		}
		if !selected {
			out = append(out, scanner.Finding{
				Severity:       scanner.SevMedium,
				Title:          fmt.Sprintf("Pod %s/%s not selected by any NetworkPolicy", p.Namespace, p.Name),
				Description:    fmt.Sprintf("Pod %s/%s is in a namespace with NetworkPolicies but no policy's podSelector matches it. It falls through to the default (allow all).", p.Namespace, p.Name),
				Resource:       podResource(p),
				Evidence:       "No NetworkPolicy.spec.podSelector matches this pod's labels",
				Impact:         "Pod has unrestricted network access despite namespace having policies for other workloads.",
				Recommendation: "Add a NetworkPolicy that selects this pod, or add a default-deny that covers all pods.",
				Tags:           []string{"network-policy", "unselected", "gap"},
			})
		}
	}
	return out
}

func ruleSA003DaemonSetSA(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, ds := range inv.DaemonSets {
		saName := ds.Spec.Template.Spec.ServiceAccountName
		if saName == "" || saName == "default" {
			continue
		}

		hasBindings := false
		for _, rb := range inv.RoleBindings {
			for _, s := range rb.Subjects {
				if s.Kind == "ServiceAccount" && s.Name == saName && (s.Namespace == "" || s.Namespace == ds.Namespace) {
					hasBindings = true
					break
				}
			}
		}
		if !hasBindings {
			for _, crb := range inv.ClusterRoleBindings {
				for _, s := range crb.Subjects {
					if s.Kind == "ServiceAccount" && s.Name == saName && (s.Namespace == "" || s.Namespace == ds.Namespace) {
						hasBindings = true
						break
					}
				}
			}
		}
		if !hasBindings {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("DaemonSet %s/%s uses privileged SA %q (token on every node)", ds.Namespace, ds.Name, saName),
			Description:    fmt.Sprintf("DaemonSet %s/%s runs SA %q with explicit RBAC bindings on every node. Compromise of any single node exposes this SA's permissions.", ds.Namespace, ds.Name, saName),
			Resource:       scanner.Resource{Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name},
			Evidence:       fmt.Sprintf("serviceAccountName=%s, has RoleBinding/ClusterRoleBinding", saName),
			Impact:         "SA token present on every node. Single node compromise grants SA permissions cluster-wide.",
			Recommendation: "Scope the SA narrowly. Consider per-node identities or node-authorization patterns.",
			Tags:           []string{"daemonset", "service-account", "blast-radius"},
		})
	}
	return out
}

type genericRole struct {
	name  string
	ns    string
	kind  string
	rules []rbacv1.PolicyRule
}

func rolesToGeneric(roles interface{}, isCluster bool) []genericRole {
	var out []genericRole
	switch r := roles.(type) {
	case []rbacv1.Role:
		for _, role := range r {
			out = append(out, genericRole{name: role.Name, ns: role.Namespace, kind: "Role", rules: role.Rules})
		}
	case []rbacv1.ClusterRole:
		for _, role := range r {
			out = append(out, genericRole{name: role.Name, ns: "", kind: "ClusterRole", rules: role.Rules})
		}
	}
	return out
}

func hasSubresource(rule rbacv1.PolicyRule, resource, subresource string) bool {
	target := resource + "/" + subresource
	return sliceHasAny(rule.APIGroups, "", "*") && sliceHasAny(rule.Resources, target, "*/"+subresource, "*")
}

func isSystemRoleAdv(name string) bool {
	return strings.HasPrefix(name, "system:") || name == "cluster-admin" || name == "admin" ||
		name == "edit" || name == "view" || strings.HasPrefix(name, "kubeadm:")
}

func isPSAViolator(p corev1.Pod) bool {
	if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC {
		return true
	}
	for _, c := range allContainers(p) {
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				return true
			}
		}
	}
	for _, v := range p.Spec.Volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}

func selectorMatchesPod(selector metav1.LabelSelector, p corev1.Pod) bool {
	for k, v := range selector.MatchLabels {
		if p.Labels[k] != v {
			return false
		}
	}
	return true
}
