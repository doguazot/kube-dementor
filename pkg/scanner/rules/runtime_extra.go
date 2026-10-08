package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func RuntimeExtrasMore(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	out = append(out, runtimeEBPFAgentExposure(inv)...)
	out = append(out, runtimeMeshPermissive(inv)...)
	out = append(out, runtimeOperatorPriv(inv)...)
	out = append(out, runtimeWebhookFailOpen(inv)...)
	out = append(out, runtimeSeccompDefault(inv)...)
	out = append(out, runtimeAppArmorMissing(inv)...)
	out = append(out, runtimeLogShipperMissing(inv)...)
	return out
}

func runtimeEBPFAgentExposure(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range p.Spec.Containers {
			img := strings.ToLower(c.Image)
			isAgent := strings.Contains(img, "/falco:") ||
				strings.Contains(img, "/tetragon:") ||
				strings.Contains(img, "/tracee:") ||
				strings.Contains(img, "kubearmor")
			if !isAgent {
				continue
			}

			for _, v := range p.Spec.Volumes {
				if v.HostPath == nil {
					continue
				}
				path := v.HostPath.Path
				if strings.Contains(path, "/falco/") || strings.Contains(path, "/tetragon/") ||
					strings.Contains(path, "/run/falco") || strings.Contains(path, "/var/run/tetragon") {
					out = append(out, scanner.Finding{
						RuleID:         "KH-RUNTIME-EBPF-EXPOSE",
						Category:       scanner.CatRuntime,
						Severity:       scanner.SevMedium,
						Title:          fmt.Sprintf("Runtime detection agent %q mounts host socket %q (potential bypass)", c.Name, path),
						Description:    "If the runtime-detection agent's UNIX socket is hostPath-mounted into another pod (or accessible from a privileged pod), an attacker can disconnect / shadow / suppress events at the source. Audit which pods can reach this socket.",
						Resource:       podResource(p),
						Evidence:       fmt.Sprintf("agent=%s hostPath=%s container=%s", img, path, c.Name),
						Impact:         "Detection silencing: attacker mutes Falco/Tetragon for the duration of the operation.",
						Recommendation: "Restrict access to the agent socket via host filesystem permissions; do not allow other workloads to mount the same hostPath.",
						Tags:           []string{"runtime", "ebpf", "detection-bypass"},
					})
				}
			}
		}
	}
	return out
}

func runtimeMeshPermissive(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding

	sidecarPodsByNs := map[string]int{}
	totalPodsByNs := map[string]int{}
	meshedNs := map[string]bool{}
	for _, n := range inv.Namespaces {
		if v, ok := n.Labels["istio-injection"]; ok && v == "enabled" {
			meshedNs[n.Name] = true
		}
	}
	for _, p := range inv.Pods {
		if !meshedNs[p.Namespace] {
			continue
		}
		totalPodsByNs[p.Namespace]++
		for _, c := range p.Spec.Containers {
			if c.Name == "istio-proxy" {
				sidecarPodsByNs[p.Namespace]++
				break
			}
		}
	}
	for ns, total := range totalPodsByNs {
		sc := sidecarPodsByNs[ns]
		if sc == total {
			continue
		}
		gap := total - sc
		out = append(out, scanner.Finding{
			RuleID:         "KH-RUNTIME-MESH-PERMISSIVE",
			Category:       scanner.CatServiceMesh,
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("Namespace %q has %d/%d pods missing the mesh sidecar", ns, gap, total),
			Description:    "An istio-injection-enabled namespace contains pods without the istio-proxy sidecar. With a permissive PeerAuthentication those pods can talk to (and be talked to by) meshed peers in plaintext, defeating mTLS.",
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns},
			Evidence:       fmt.Sprintf("ns=%s sidecar-pods=%d total-pods=%d", ns, sc, total),
			Impact:         "Mesh bypass: a compromised non-mesh pod inside this namespace can reach service VIPs cleartext.",
			Recommendation: "Enforce sidecar injection (`sidecar.istio.io/inject: \"true\"` annotation), make PeerAuthentication STRICT, and monitor for un-meshed pods.",
			Tags:           []string{"runtime", "service-mesh", "permissive"},
		})
	}
	return out
}

func runtimeOperatorPriv(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	highValueOperators := []struct {
		match string
		name  string
	}{
		{"argocd", "Argo CD"},
		{"flux", "Flux"},
		{"velero", "Velero"},
		{"cert-manager", "cert-manager"},
		{"external-secrets", "External Secrets Operator"},
		{"vault-agent", "Vault Agent"},
		{"trident", "NetApp Trident"},
		{"rancher", "Rancher"},
	}

	clusterAdminSAs := map[string]bool{}
	for _, crb := range inv.ClusterRoleBindings {
		if crb.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, s := range crb.Subjects {
			if s.Kind == "ServiceAccount" {
				clusterAdminSAs[s.Namespace+"/"+s.Name] = true
			}
		}
	}
	for _, p := range inv.Pods {
		nm := strings.ToLower(p.Name)
		var matched string
		for _, op := range highValueOperators {
			if strings.Contains(nm, op.match) {
				matched = op.name
				break
			}
		}
		if matched == "" {
			continue
		}
		sa := p.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		if !clusterAdminSAs[p.Namespace+"/"+sa] {
			continue
		}
		out = append(out, scanner.Finding{
			RuleID:         "KH-RUNTIME-OPERATOR-PRIV",
			Category:       scanner.CatRuntime,
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("%s pod runs as cluster-admin SA on %s/%s", matched, p.Namespace, p.Name),
			Description:    "High-value controller pods that hold cluster-admin RBAC become single-shot game-over targets. A pod compromise (CVE in the controller, supply-chain image swap, etc.) yields full cluster control.",
			Resource:       podResource(p),
			Evidence:       fmt.Sprintf("operator=%s sa=%s/%s permission=cluster-admin", matched, p.Namespace, sa),
			Impact:         "Pod RCE → cluster-admin. Lateral movement to every node and namespace.",
			Recommendation: "Replace cluster-admin with a least-privilege ClusterRole carrying only the verbs/resources the controller actually needs; many of these operators publish a 'restricted' ClusterRole alternative.",
			Tags:           []string{"runtime", "operator", "rbac"},
		})
	}
	return out
}

func runtimeWebhookFailOpen(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	for _, v := range inv.ValidatingWebhooks {
		nm := strings.ToLower(v.Name)
		if !strings.Contains(nm, "kyverno") && !strings.Contains(nm, "gatekeeper") &&
			!strings.Contains(nm, "policy") {
			continue
		}
		for _, w := range v.Webhooks {
			fp := "Fail"
			if w.FailurePolicy != nil {
				fp = string(*w.FailurePolicy)
			}
			if fp == "Ignore" {
				out = append(out, scanner.Finding{
					RuleID:         "KH-RUNTIME-WEBHOOK-FAIL-OPEN",
					Category:       scanner.CatRuntime,
					Severity:       scanner.SevHigh,
					Title:          fmt.Sprintf("Policy webhook %q (likely OPA/Kyverno) fails open", v.Name),
					Description:    "Killing the policy-engine pod (or blocking its NetworkPolicy) silently disables all of its rules until the pod is back. This is a common pre-step before deploying a privileged backdoor.",
					Resource:       scanner.Resource{Kind: "ValidatingWebhookConfiguration", Name: v.Name},
					Evidence:       fmt.Sprintf("webhook=%s failurePolicy=Ignore", w.Name),
					Impact:         "Policy bypass: a momentary outage of the policy engine = period of fully open admission.",
					Recommendation: "Set failurePolicy=Fail; run multiple replicas; protect with a PodDisruptionBudget.",
					Tags:           []string{"runtime", "policy", "fail-open"},
				})
			}
		}
	}
	return out
}

func runtimeSeccompDefault(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	missing := 0
	for _, p := range inv.Pods {

		if strings.HasPrefix(p.Namespace, "kube-") {
			continue
		}
		hasProfile := false
		if p.Spec.SecurityContext != nil && p.Spec.SecurityContext.SeccompProfile != nil {
			hasProfile = true
		}
		for _, c := range p.Spec.Containers {
			if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
				hasProfile = true
				break
			}
		}
		if !hasProfile {
			missing++
		}
	}
	total := len(inv.Pods)
	if total == 0 || missing == 0 {
		return nil
	}
	if missing*100/total < 30 {
		return nil
	}
	out = append(out, scanner.Finding{
		RuleID:         "KH-RUNTIME-SECCOMP-DEFAULT",
		Category:       scanner.CatRuntime,
		Severity:       scanner.SevMedium,
		Title:          fmt.Sprintf("%d/%d pods (%.0f%%) have no seccompProfile and rely on kubelet default", missing, total, float64(missing*100)/float64(total)),
		Description:    "Without an explicit seccompProfile (RuntimeDefault or Localhost) the container has the unrestricted syscall surface. A kernel-LPE CVE that requires a syscall not in the default seccomp profile becomes exploitable.",
		Resource:       scanner.Resource{Kind: "Cluster"},
		Evidence:       fmt.Sprintf("pods-missing-seccomp=%d total=%d", missing, total),
		Impact:         "Larger kernel-attack surface for any container compromise.",
		Recommendation: "Set `securityContext.seccompProfile.type: RuntimeDefault` cluster-wide via PSA-restricted, or pass `--seccomp-default=true` to every kubelet (Kubernetes 1.27+).",
		Tags:           []string{"runtime", "seccomp"},
	})
	return out
}

func runtimeAppArmorMissing(inv *scanner.Inventory) []scanner.Finding {
	withProfile := 0
	for _, p := range inv.Pods {
		if v, ok := p.Annotations["container.apparmor.security.beta.kubernetes.io/all"]; ok && v != "" {
			withProfile++
			continue
		}
		for _, c := range p.Spec.Containers {
			key := "container.apparmor.security.beta.kubernetes.io/" + c.Name
			if v, ok := p.Annotations[key]; ok && v != "" {
				withProfile++
				break
			}
		}
	}
	if withProfile > 0 {
		return nil
	}
	if len(inv.Pods) == 0 {
		return nil
	}
	return []scanner.Finding{{
		RuleID:         "KH-RUNTIME-APPARMOR-MISSING",
		Category:       scanner.CatRuntime,
		Severity:       scanner.SevLow,
		Title:          "No pod uses an AppArmor profile",
		Description:    "AppArmor (or SELinux) is the LSM layer most kernels rely on for fine-grained MAC. Annotating pods with `container.apparmor.security.beta.kubernetes.io/<container>: localhost/profile-name` enforces an MAC profile per workload.",
		Resource:       scanner.Resource{Kind: "Cluster"},
		Evidence:       fmt.Sprintf("pods-with-apparmor=0 of %d", len(inv.Pods)),
		Impact:         "No mandatory-access-control narrowing of the syscall + filesystem surface beyond the kernel default.",
		Recommendation: "Build per-workload AppArmor profiles (e.g. via `bane`) and set the annotation.",
		Tags:           []string{"runtime", "apparmor", "lsm"},
	}}
}

func runtimeLogShipperMissing(inv *scanner.Inventory) []scanner.Finding {
	known := []string{"fluent-bit", "fluentd", "vector", "promtail", "filebeat", "logstash", "datadog-agent", "splunk-otel"}
	for _, ds := range inv.DaemonSets {
		nm := strings.ToLower(ds.Name)
		for _, k := range known {
			if strings.Contains(nm, k) {
				return nil
			}
		}
	}
	for _, p := range inv.Pods {
		nm := strings.ToLower(p.Name)
		for _, k := range known {
			if strings.Contains(nm, k) {
				return nil
			}
		}
	}
	return []scanner.Finding{{
		RuleID:         "KH-RUNTIME-LOG-SHIPPER-MISSING",
		Category:       scanner.CatRuntime,
		Severity:       scanner.SevMedium,
		Title:          "No log-shipper DaemonSet detected (Fluent Bit / Vector / Promtail / etc.)",
		Description:    "Without a centralized log shipper, container stdout/stderr stays only on the node and is rotated. Attacker actions (especially short-lived pods) leave no trace once the pod is GC'd.",
		Resource:       scanner.Resource{Kind: "Cluster"},
		Evidence:       "no DaemonSet matched fluent-bit / fluentd / vector / promtail / filebeat / datadog-agent",
		Impact:         "Forensic blackout post-incident; SIEM has no view into pod-level events.",
		Recommendation: "Install Fluent Bit / Vector / Promtail (or vendor agent) as a DaemonSet and forward to a SIEM.",
		Tags:           []string{"runtime", "logging", "forensics"},
	}}
}
