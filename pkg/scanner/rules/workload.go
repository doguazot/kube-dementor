package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
)

func WorkloadRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-WRK-001", Title: "Privileged container", Category: scanner.CatWorkload, Fn: ruleWRK001Privileged},
		{ID: "KH-WRK-002", Title: "Dangerous hostPath mount", Category: scanner.CatWorkload, Fn: ruleWRK002HostPath},
		{ID: "KH-WRK-003", Title: "hostPID/hostNetwork/hostIPC enabled", Category: scanner.CatWorkload, Fn: ruleWRK003HostNamespaces},
		{ID: "KH-WRK-004", Title: "Container running as root", Category: scanner.CatWorkload, Fn: ruleWRK004RunAsRoot},
		{ID: "KH-WRK-005", Title: "Dangerous Linux capabilities", Category: scanner.CatWorkload, Fn: ruleWRK005Capabilities},
		{ID: "KH-WRK-006", Title: "Writable root filesystem", Category: scanner.CatWorkload, Fn: ruleWRK006WritableRoot},
		{ID: "KH-WRK-007", Title: "Privilege escalation allowed", Category: scanner.CatWorkload, Fn: ruleWRK007AllowPrivEsc},
		{ID: "KH-WRK-008", Title: "Docker socket mounted", Category: scanner.CatWorkload, Fn: ruleWRK008DockerSock},
		{ID: "KH-WRK-009", Title: "No seccomp profile", Category: scanner.CatWorkload, Fn: ruleWRK009NoSeccomp},
		{ID: "KH-WRK-010", Title: "Using default service account", Category: scanner.CatWorkload, Fn: ruleWRK010DefaultSA},
		{ID: "KH-WRK-011", Title: "Automount service account token", Category: scanner.CatWorkload, Fn: ruleWRK011AutomountSA},
		{ID: "KH-WRK-012", Title: "Latest / mutable image tag", Category: scanner.CatWorkload, Fn: ruleWRK012LatestTag},
		{ID: "KH-WRK-013", Title: "No resource limits", Category: scanner.CatWorkload, Fn: ruleWRK013NoLimits},
		{ID: "KH-WRK-014", Title: "Image pulled from untrusted registry", Category: scanner.CatWorkload, Fn: ruleWRK014UntrustedRegistry},
		{ID: "KH-WRK-015", Title: "Sensitive env vars in spec", Category: scanner.CatWorkload, Fn: ruleWRK015SensitiveEnv},
	}
}

func ruleWRK001Privileged(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			if c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevCritical,
				Title:          "Privileged container detected",
				Description:    fmt.Sprintf("Container %q in pod %s/%s runs with privileged=true. Privileged containers bypass nearly all container isolation and effectively run as root on the node.", c.Name, p.Namespace, p.Name),
				Resource:       podResource(p),
				Evidence:       fmt.Sprintf("spec.containers[%s].securityContext.privileged=true", c.Name),
				Impact:         "Container escape to host, read/write all node resources, steal kubelet credentials, pivot to other nodes.",
				Recommendation: "Remove privileged: true. Grant only the specific Linux capabilities actually required via capabilities.add, and pair with readOnlyRootFilesystem + seccomp profile.",
				RemediationYAML: fmt.Sprintf(`spec:
  containers:
  - name: %s
    securityContext:
      privileged: false          # <-- change
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]`, c.Name),
				RemediationCmd: fmt.Sprintf("kubectl patch pod %s -n %s -p '{\"spec\":{\"containers\":[{\"name\":\"%s\",\"securityContext\":{\"privileged\":false}}]}}'", p.Name, p.Namespace, c.Name),
				References:     []string{"CIS 5.2.1", "MITRE T1611"},
				MitreATTACK:    []string{"T1611"},
				Tags:           []string{"container-escape", "privileged"},
			})
		}
	}
	return out
}

func ruleWRK002HostPath(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			hp := v.HostPath.Path
			sev := scanner.SevHigh
			if isCriticalHostPath(hp) {
				sev = scanner.SevCritical
			}

			rw := false
			for _, c := range allContainers(p) {
				for _, vm := range c.VolumeMounts {
					if vm.Name == v.Name && !vm.ReadOnly {
						rw = true
					}
				}
			}
			title := "HostPath volume mount"
			if rw {
				title += " (read-write)"
			} else {
				title += " (read-only)"
				if sev == scanner.SevCritical {
					sev = scanner.SevHigh
				}
			}
			out = append(out, scanner.Finding{
				Severity:       sev,
				Title:          title,
				Description:    fmt.Sprintf("Pod %s/%s mounts host path %q. This grants direct access to the underlying node's filesystem.", p.Namespace, p.Name, hp),
				Resource:       podResource(p),
				Evidence:       fmt.Sprintf("spec.volumes[%s].hostPath.path=%s readWrite=%v", v.Name, hp, rw),
				Impact:         "Read SSH keys, kubelet credentials and tokens from the host. Write systemd units or crons for persistence. With read-write on /var/run/docker.sock, trivial container escape.",
				Recommendation: "Remove the hostPath mount. If node data is truly required, use a projected or PVC mount, or at minimum set readOnly: true and restrict to a specific file (not a directory).",
				RemediationYAML: `# Remove the hostPath volume from .spec.volumes
# and the matching volumeMounts from each container.
# If absolutely necessary, scope tightly:
#   volumes:
#   - name: cert
#     hostPath:
#       path: /etc/kubernetes/pki/ca.crt
#       type: File
#   volumeMounts:
#   - name: cert
#     mountPath: /ca.crt
#     readOnly: true`,
				References:  []string{"CIS 5.2.9", "MITRE T1611"},
				MitreATTACK: []string{"T1611"},
				Tags:        []string{"container-escape", "hostpath"},
			})
		}
	}
	return out
}

func ruleWRK003HostNamespaces(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		flags := []string{}
		if p.Spec.HostPID {
			flags = append(flags, "hostPID")
		}
		if p.Spec.HostNetwork {
			flags = append(flags, "hostNetwork")
		}
		if p.Spec.HostIPC {
			flags = append(flags, "hostIPC")
		}
		if len(flags) == 0 {
			continue
		}
		sev := scanner.SevHigh
		if len(flags) == 3 {
			sev = scanner.SevCritical
		}
		out = append(out, scanner.Finding{
			Severity:       sev,
			Title:          "Host namespace(s) shared with pod: " + strings.Join(flags, ", "),
			Description:    fmt.Sprintf("Pod %s/%s shares %s with the host.", p.Namespace, p.Name, strings.Join(flags, "+")),
			Resource:       podResource(p),
			Evidence:       fmt.Sprintf("spec.hostPID=%v hostNetwork=%v hostIPC=%v", p.Spec.HostPID, p.Spec.HostNetwork, p.Spec.HostIPC),
			Impact:         "hostPID exposes processes of all pods on the node and enables nsenter to the host. hostNetwork bypasses NetworkPolicies and exposes localhost services (kubelet, etcd). hostIPC allows shared memory attacks.",
			Recommendation: "Disable hostPID/hostNetwork/hostIPC unless strictly needed. Use PodSecurityAdmission restricted profile or a policy engine (Kyverno/Gatekeeper) to enforce this cluster-wide.",
			RemediationYAML: `spec:
  hostPID: false
  hostNetwork: false
  hostIPC: false`,
			References:  []string{"CIS 5.2.2-5.2.4", "MITRE T1611"},
			MitreATTACK: []string{"T1611"},
			Tags:        []string{"container-escape", "host-namespaces"},
		})
	}
	return out
}

func ruleWRK004RunAsRoot(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			if runsAsRoot(p, c) {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevMedium,
					Title:          "Container may run as UID 0",
					Description:    fmt.Sprintf("Container %q in pod %s/%s does not specify runAsNonRoot=true or a non-zero runAsUser. If the image runs as root, the container will run as root.", c.Name, p.Namespace, p.Name),
					Resource:       podResource(p),
					Evidence:       "No runAsNonRoot=true and no runAsUser>0",
					Impact:         "Root inside the container makes container-escape exploits much easier (filesystem write, capability abuse).",
					Recommendation: "Set securityContext.runAsNonRoot: true and runAsUser/runAsGroup to a non-privileged UID (>=10000). Rebuild the image with a USER directive.",
					RemediationYAML: fmt.Sprintf(`spec:
  containers:
  - name: %s
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
      runAsGroup: 10001`, c.Name),
					References:  []string{"CIS 5.2.5"},
					MitreATTACK: []string{"T1068"},
					Tags:        []string{"workload", "runasroot"},
				})
			}
		}
	}
	return out
}

var dangerousCaps = map[string]string{
	"SYS_ADMIN":       "grants almost all kernel admin functionality; equivalent to root",
	"SYS_MODULE":      "can load kernel modules - trivial node takeover",
	"SYS_PTRACE":      "can trace/attach to any process on the node",
	"SYS_RAWIO":       "raw disk access; can read/write any block device",
	"NET_ADMIN":       "configures networking; can set up MITM, disrupt cluster DNS",
	"NET_RAW":         "raw packet capture / crafting",
	"DAC_READ_SEARCH": "bypass file read permission checks",
	"DAC_OVERRIDE":    "bypass file read/write/execute permission checks",
	"SETUID":          "set arbitrary UID",
	"SETGID":          "set arbitrary GID",
	"CHOWN":           "arbitrary chown",
	"KILL":            "send signals to arbitrary processes",
	"BPF":             "load BPF programs - can read kernel memory",
}

func ruleWRK005Capabilities(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
				continue
			}
			var added []string
			for _, cap := range c.SecurityContext.Capabilities.Add {
				name := strings.TrimPrefix(strings.ToUpper(string(cap)), "CAP_")
				if _, ok := dangerousCaps[name]; ok {
					added = append(added, name)
				}
			}
			if len(added) == 0 {
				continue
			}
			sev := scanner.SevHigh
			for _, c := range added {
				if c == "SYS_ADMIN" || c == "SYS_MODULE" || c == "SYS_RAWIO" || c == "BPF" {
					sev = scanner.SevCritical
					break
				}
			}
			var reasons []string
			for _, cp := range added {
				reasons = append(reasons, cp+" ("+dangerousCaps[cp]+")")
			}
			out = append(out, scanner.Finding{
				Severity:       sev,
				Title:          "Dangerous Linux capability granted: " + strings.Join(added, ", "),
				Description:    fmt.Sprintf("Container %q in pod %s/%s explicitly adds dangerous capabilities.", c.Name, p.Namespace, p.Name),
				Resource:       podResource(p),
				Evidence:       strings.Join(reasons, "; "),
				Impact:         "Any of these capabilities is typically enough to escape the container or pivot on the host.",
				Recommendation: "Drop ALL capabilities and only add the minimum required. Prefer CAP_NET_BIND_SERVICE (<1024 ports) over NET_ADMIN.",
				RemediationYAML: fmt.Sprintf(`spec:
  containers:
  - name: %s
    securityContext:
      capabilities:
        drop: ["ALL"]
        add: []  # add only strictly required caps`, c.Name),
				References:  []string{"CIS 5.2.8", "MITRE T1611"},
				MitreATTACK: []string{"T1611"},
				Tags:        []string{"container-escape", "capabilities"},
			})
		}
	}
	return out
}

func ruleWRK006WritableRoot(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			if c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevLow,
				Title:          "Container has writable root filesystem",
				Description:    fmt.Sprintf("Container %q in pod %s/%s does not set readOnlyRootFilesystem=true.", c.Name, p.Namespace, p.Name),
				Resource:       podResource(p),
				Evidence:       "securityContext.readOnlyRootFilesystem != true",
				Impact:         "Attackers with RCE in the container can drop and execute secondary tooling.",
				Recommendation: "Set readOnlyRootFilesystem: true and mount an emptyDir volume for any paths that truly need to be writable.",
				Tags:           []string{"workload", "hardening"},
			})
		}
	}
	return out
}

func ruleWRK007AllowPrivEsc(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			allowed := true
			if c.SecurityContext != nil && c.SecurityContext.AllowPrivilegeEscalation != nil {
				allowed = *c.SecurityContext.AllowPrivilegeEscalation
			}
			if !allowed {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevMedium,
				Title:          "allowPrivilegeEscalation not disabled",
				Description:    fmt.Sprintf("Container %q in pod %s/%s does not explicitly set allowPrivilegeEscalation=false.", c.Name, p.Namespace, p.Name),
				Resource:       podResource(p),
				Evidence:       "securityContext.allowPrivilegeEscalation is nil or true",
				Impact:         "setuid binaries inside the container may gain more privileges than the parent process.",
				Recommendation: "Set allowPrivilegeEscalation: false on all workloads.",
				Tags:           []string{"workload", "hardening"},
			})
		}
	}
	return out
}

func ruleWRK008DockerSock(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			p2 := strings.ToLower(v.HostPath.Path)
			if !(strings.Contains(p2, "docker.sock") || strings.Contains(p2, "containerd.sock") || strings.Contains(p2, "crio.sock")) {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevCritical,
				Title:          "Container runtime socket mounted in pod",
				Description:    fmt.Sprintf("Pod %s/%s mounts %s. This grants complete control over the node's container runtime.", p.Namespace, p.Name, v.HostPath.Path),
				Resource:       podResource(p),
				Evidence:       "hostPath " + v.HostPath.Path,
				Impact:         "Trivial container escape: start any container with --privileged --pid=host, arbitrary code execution on the node as root.",
				Recommendation: "Never mount the container runtime socket in application pods. If a legitimate use-case exists (DinD, build pods), isolate those pods on dedicated nodes and restrict network access.",
				References:     []string{"MITRE T1611"},
				MitreATTACK:    []string{"T1611"},
				Tags:           []string{"container-escape", "critical"},
			})
		}
	}
	return out
}

func ruleWRK009NoSeccomp(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		hasPod := p.Spec.SecurityContext != nil && p.Spec.SecurityContext.SeccompProfile != nil &&
			p.Spec.SecurityContext.SeccompProfile.Type != "" && p.Spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined
		for _, c := range allContainers(p) {
			hasC := c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil &&
				c.SecurityContext.SeccompProfile.Type != "" && c.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined
			if hasPod || hasC {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevLow,
				Title:          "No seccomp profile configured",
				Description:    fmt.Sprintf("Container %q in pod %s/%s has no seccomp profile or uses Unconfined.", c.Name, p.Namespace, p.Name),
				Resource:       podResource(p),
				Evidence:       "missing seccompProfile.type=RuntimeDefault|Localhost",
				Recommendation: "Set seccompProfile.type: RuntimeDefault on the pod (or a Localhost profile).",
				Tags:           []string{"workload", "hardening"},
			})
			break
		}
	}
	return out
}

func ruleWRK010DefaultSA(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		if p.Spec.ServiceAccountName != "" && p.Spec.ServiceAccountName != "default" {
			continue
		}
		if !scanner.AutomountToken(inv, &p) {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          "Pod uses default ServiceAccount with automount token",
			Description:    fmt.Sprintf("Pod %s/%s uses the 'default' ServiceAccount and auto-mounts its token.", p.Namespace, p.Name),
			Resource:       podResource(p),
			Evidence:       "spec.serviceAccountName=default / empty, automount=true",
			Impact:         "Any RCE inside the pod yields at minimum the 'default' SA's privileges. If the default SA was granted extra roles (a common misconfig), full privilege escalation.",
			Recommendation: "Create a purpose-built ServiceAccount with least privilege, or set automountServiceAccountToken: false.",
			RemediationYAML: `spec:
  serviceAccountName: my-app-sa     # explicit, minimal SA
  automountServiceAccountToken: false`,
			Tags: []string{"rbac", "default-sa"},
		})
	}
	return out
}

func ruleWRK011AutomountSA(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		if !scanner.HasServiceAccountToken(inv, &p) {
			continue
		}

		name := p.Spec.ServiceAccountName
		if name == "default" {
			continue
		}

		hasBinding := false
		for _, rb := range inv.RoleBindings {
			for _, s := range rb.Subjects {
				if s.Kind == "ServiceAccount" && s.Name == name && s.Namespace == p.Namespace {
					hasBinding = true
					break
				}
			}
		}
		for _, crb := range inv.ClusterRoleBindings {
			for _, s := range crb.Subjects {
				if s.Kind == "ServiceAccount" && s.Name == name && s.Namespace == p.Namespace {
					hasBinding = true
					break
				}
			}
		}
		if !hasBinding {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevLow,
			Title:          "Service account token auto-mounted into pod",
			Description:    fmt.Sprintf("Pod %s/%s uses SA %q and has automountServiceAccountToken unset (default true).", p.Namespace, p.Name, name),
			Resource:       podResource(p),
			Evidence:       "automountServiceAccountToken unset",
			Recommendation: "Set automountServiceAccountToken: false on pods that do not call the Kubernetes API.",
			Tags:           []string{"rbac", "token-mount"},
		})
	}
	return out
}

func ruleWRK012LatestTag(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			image := c.Image
			if image == "" {
				continue
			}
			if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevLow,
					Title:          "Image uses mutable 'latest' tag",
					Description:    fmt.Sprintf("Container %q in pod %s/%s uses image %q which has no immutable tag.", c.Name, p.Namespace, p.Name, image),
					Resource:       podResource(p),
					Evidence:       "image=" + image,
					Impact:         "Non-reproducible deploys, difficult incident forensics, vulnerable to registry tag hijack.",
					Recommendation: "Pin images by digest (image@sha256:...) or immutable tag.",
					Tags:           []string{"supply-chain"},
				})
			}
		}
	}
	return out
}

func ruleWRK013NoLimits(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			if _, ok := c.Resources.Limits["cpu"]; !ok {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevInfo,
					Title:          "No CPU/memory limits set",
					Description:    fmt.Sprintf("Container %q in pod %s/%s has no resource limits.", c.Name, p.Namespace, p.Name),
					Resource:       podResource(p),
					Recommendation: "Set resources.limits.cpu and resources.limits.memory to prevent noisy-neighbor DoS.",
					Tags:           []string{"availability"},
				})
				break
			}
		}
	}
	return out
}

var trustedRegistries = []string{
	"registry.k8s.io", "k8s.gcr.io", "gcr.io", "docker.io", "quay.io", "ghcr.io",
}

func ruleWRK014UntrustedRegistry(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			image := strings.ToLower(c.Image)
			if image == "" {
				continue
			}

			parts := strings.SplitN(image, "/", 2)
			reg := ""
			if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
				reg = parts[0]
			}
			if reg == "" {
				continue
			}
			trusted := false
			for _, t := range trustedRegistries {
				if strings.Contains(reg, t) {
					trusted = true
					break
				}
			}
			if trusted {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevLow,
				Title:          "Image from non-standard registry",
				Description:    fmt.Sprintf("Container %q in pod %s/%s pulls from %q.", c.Name, p.Namespace, p.Name, reg),
				Resource:       podResource(p),
				Evidence:       "image=" + c.Image,
				Recommendation: "Mirror images to an internal registry, enforce with admission policy (ImagePolicyWebhook / Kyverno) and verify signatures (Cosign/Sigstore).",
				Tags:           []string{"supply-chain"},
			})
		}
	}
	return out
}

var sensitiveEnvKeywords = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "access_key", "private_key"}

func ruleWRK015SensitiveEnv(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			for _, env := range c.Env {
				if env.Value == "" || env.ValueFrom != nil {
					continue
				}
				lc := strings.ToLower(env.Name)
				for _, kw := range sensitiveEnvKeywords {
					if strings.Contains(lc, kw) {
						out = append(out, scanner.Finding{
							Severity:       scanner.SevHigh,
							Title:          "Potential secret in plaintext env var",
							Description:    fmt.Sprintf("Container %q in pod %s/%s defines env %q inline (not from a Secret).", c.Name, p.Namespace, p.Name, env.Name),
							Resource:       podResource(p),
							Evidence:       "env." + env.Name + " = <redacted>",
							Impact:         "Secrets in env are visible via `kubectl describe pod` to anyone with get-pod permission, leaked into logs and crash dumps.",
							Recommendation: "Store secrets in a Kubernetes Secret (or external vault) and reference via envFrom / env.valueFrom.secretKeyRef.",
							RemediationYAML: fmt.Sprintf(`env:
- name: %s
  valueFrom:
    secretKeyRef:
      name: %s-secret
      key: %s`, env.Name, c.Name, strings.ToLower(env.Name)),
							Tags: []string{"secret", "leak"},
						})
						break
					}
				}
			}
		}
	}
	return out
}

func allContainers(p corev1.Pod) []corev1.Container {
	return scanner.Containers(&p)
}

func podResource(p corev1.Pod) scanner.Resource {
	return scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name, UID: string(p.UID)}
}

func runsAsRoot(p corev1.Pod, c corev1.Container) bool {

	if c.SecurityContext != nil {
		if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
			return true
		}
		if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser > 0 {
			return false
		}
		if c.SecurityContext.RunAsNonRoot != nil {
			return !*c.SecurityContext.RunAsNonRoot
		}
	}
	if p.Spec.SecurityContext != nil {
		if p.Spec.SecurityContext.RunAsUser != nil && *p.Spec.SecurityContext.RunAsUser == 0 {
			return true
		}
		if p.Spec.SecurityContext.RunAsUser != nil && *p.Spec.SecurityContext.RunAsUser > 0 {
			return false
		}
		if p.Spec.SecurityContext.RunAsNonRoot != nil {
			return !*p.Spec.SecurityContext.RunAsNonRoot
		}
	}
	return true
}

func isCriticalHostPath(path string) bool {
	path = strings.TrimRight(path, "/")
	if path == "" {
		return true
	}
	switch path {
	case "/", "/etc", "/var", "/root", "/proc", "/sys",
		"/var/run/docker.sock", "/var/run/containerd/containerd.sock",
		"/etc/kubernetes", "/var/lib/kubelet", "/var/lib/docker":
		return true
	}
	return false
}
