package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	netv1 "k8s.io/api/networking/v1"
)

func CNIRulesStatic(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	out = append(out, cniDetect(inv)...)
	out = append(out, npBypassDetect(inv)...)
	out = append(out, dnsPoisonEnabler(inv)...)
	out = append(out, ciliumAgentAPI(inv)...)
	out = append(out, calicoFelixMetrics(inv)...)
	out = append(out, coreDNSRewriteCheck(inv)...)
	out = append(out, externalIPsCheck(inv)...)
	return out
}

func ciliumAgentAPI(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		isCiliumAgent := false
		for _, c := range p.Spec.Containers {
			if strings.Contains(strings.ToLower(c.Image), "cilium/cilium") {
				isCiliumAgent = true
			}
		}
		if isCiliumAgent {
			continue
		}

		for _, v := range p.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			path := strings.ToLower(v.HostPath.Path)
			if strings.Contains(path, "/var/run/cilium") || strings.Contains(path, "cilium.sock") {
				out = append(out, scanner.Finding{
					RuleID:         "KH-CNI-CILIUM-AGENT-API",
					Category:       scanner.CatCNI,
					Severity:       scanner.SevHigh,
					Title:          fmt.Sprintf("Pod %s/%s mounts the Cilium agent socket", p.Namespace, p.Name),
					Description:    "Cilium's agent UNIX socket allows full programmatic control over CNI policy, endpoint mappings, and identity assignments. Any pod with this socket mounted can issue requests as the agent.",
					Resource:       podResource(p),
					Evidence:       fmt.Sprintf("hostPath=%s container_in_pod=%s", v.HostPath.Path, v.Name),
					Impact:         "CNI control-plane takeover from inside a workload pod: rewrite NetworkPolicy, identity, and routing.",
					Recommendation: "Remove the hostPath mount unless the pod is the agent itself; constrain via Pod Security Admission.",
					Tags:           []string{"cni", "cilium", "agent-api"},
				})
			}
		}
	}
	return out
}

func calicoFelixMetrics(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Services {
		if !strings.Contains(strings.ToLower(s.Name), "felix") &&
			!strings.Contains(strings.ToLower(s.Name), "calico") {
			continue
		}
		for _, port := range s.Spec.Ports {
			if port.Port == 9091 || port.Port == 9092 || port.TargetPort.IntValue() == 9091 {
				out = append(out, scanner.Finding{
					RuleID:         "KH-CNI-CALICO-FELIX-METRICS",
					Category:       scanner.CatCNI,
					Severity:       scanner.SevLow,
					Title:          fmt.Sprintf("Calico Felix metrics Service %s/%s exposes diagnostic endpoint", s.Namespace, s.Name),
					Description:    "Felix's metrics/health port is open via this Service. Inside the cluster, anyone able to reach the Service can pull NetworkPolicy stats and endpoint counts — useful recon for evading enforcement.",
					Resource:       scanner.Resource{Kind: "Service", Namespace: s.Namespace, Name: s.Name},
					Evidence:       fmt.Sprintf("port=%d targetPort=%v", port.Port, port.TargetPort),
					Impact:         "Information disclosure about CNI policy posture.",
					Recommendation: "Restrict Felix metrics port via NetworkPolicy to monitoring stack only.",
					Tags:           []string{"cni", "calico", "felix"},
				})
			}
		}
	}
	return out
}

func coreDNSRewriteCheck(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	for _, cm := range inv.ConfigMaps {
		if cm.Namespace != "kube-system" {
			continue
		}
		if cm.Name != "coredns" && cm.Name != "kube-dns" {
			continue
		}
		corefile, ok := cm.Data["Corefile"]
		if !ok {
			continue
		}
		hasRewrite := strings.Contains(strings.ToLower(corefile), "rewrite ")
		hasExternalForward := false
		for _, line := range strings.Split(corefile, "\n") {
			ll := strings.TrimSpace(strings.ToLower(line))
			if !strings.HasPrefix(ll, "forward ") {
				continue
			}

			if strings.Contains(ll, "/etc/resolv.conf") {
				continue
			}
			hasExternalForward = true
			break
		}
		if !hasRewrite && !hasExternalForward {
			continue
		}
		evidence := []string{}
		if hasRewrite {
			evidence = append(evidence, "rewrite plugin enabled")
		}
		if hasExternalForward {
			evidence = append(evidence, "non-resolv.conf forward upstream")
		}
		out = append(out, scanner.Finding{
			RuleID:         "KH-CNI-COREDNS-REWRITE",
			Category:       scanner.CatCNI,
			Severity:       scanner.SevMedium,
			Title:          "CoreDNS Corefile contains rewrite/forward primitives that enable MITM",
			Description:    "The `rewrite` and externally-pointed `forward` plugins make CoreDNS a powerful MITM primitive: any attacker with patch access to the Corefile (KH-NET-012) can transparently redirect DNS for arbitrary in-cluster services.",
			Resource:       scanner.Resource{Kind: "ConfigMap", Namespace: cm.Namespace, Name: cm.Name},
			Evidence:       strings.Join(evidence, ", "),
			Impact:         "DNS hijack primitive: tied with KH-NET-012, lets attackers redirect kube-internal lookups (oauth IdP, S3, internal APIs) to attacker-controlled endpoints.",
			Recommendation: "Audit the Corefile; ensure `forward` upstreams are trusted and review who has write access to this ConfigMap.",
			Tags:           []string{"cni", "coredns", "rewrite", "mitm-primitive"},
		})
	}
	return out
}

func externalIPsCheck(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Services {
		if len(s.Spec.ExternalIPs) == 0 {
			continue
		}
		out = append(out, scanner.Finding{
			RuleID:         "KH-CNI-EXTERNAL-IPS-MITM",
			Category:       scanner.CatCNI,
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("Service %s/%s declares externalIPs (CVE-2020-8554 vector)", s.Namespace, s.Name),
			Description:    "Setting `spec.externalIPs` on a Service makes the kube-proxy capture traffic for those IPs at every node. An attacker with `create services` permission could declare an externalIP that targets a sensitive in-cluster IP and silently hijack the traffic. Public CVE-2020-8554 details the technique.",
			Resource:       scanner.Resource{Kind: "Service", Namespace: s.Namespace, Name: s.Name},
			Evidence:       fmt.Sprintf("externalIPs=%v", s.Spec.ExternalIPs),
			Impact:         "Full L4 MITM for any IP the attacker chooses, cluster-wide.",
			Recommendation: "Block externalIPs Service field via an admission policy (Kyverno/Gatekeeper rule) or a custom webhook. See https://github.com/kubernetes/kubernetes/issues/97076 for the canonical mitigation.",
			Tags:           []string{"cni", "external-ips", "cve-2020-8554"},
		})
	}
	return out
}

type cniSignature struct {
	Name        string
	ImageHint   []string
	NSHint      string
	KnownIssues string
}

var cniSignatures = []cniSignature{
	{"Calico", []string{"calico/node", "calico/cni", "calico/kube-controllers", "tigera/"}, "calico-system",
		"Versions < v3.26 have several known NetworkPolicy evaluation bugs on multi-interface pods."},
	{"Cilium", []string{"cilium/cilium", "cilium/operator-generic", "cilium/hubble"}, "kube-system",
		"CiliumNetworkPolicy overrides standard NetworkPolicy; gaps between the two can silently allow traffic. Also check clusterMesh TLS if multi-cluster is used."},
	{"Flannel", []string{"flannel/flannel", "rancher/mirrored-flannelcni", "coreos/flannel"}, "kube-flannel",
		"Flannel enforces NO NetworkPolicy by default — if another enforcer isn't installed, NetworkPolicies are non-effective."},
	{"Weave Net", []string{"weaveworks/weave-kube"}, "kube-system",
		"Weave-Net deprecated as of 2024; check for unpatched CVE-2022-29162-like escape paths."},
	{"Antrea", []string{"antrea/antrea-agent"}, "kube-system", ""},
	{"kube-router", []string{"cloudnativelabs/kube-router"}, "kube-system", ""},
	{"AWS VPC CNI", []string{"amazon-k8s-cni", "602401143452.dkr.ecr"}, "kube-system",
		"Does NOT enforce NetworkPolicy by itself. Pair with Calico for enforcement, or NetworkPolicies are purely documentation."},
}

func cniDetect(inv *scanner.Inventory) []scanner.Finding {
	seen := map[string]bool{}
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range append(p.Spec.Containers, p.Spec.InitContainers...) {
			img := strings.ToLower(c.Image)
			for _, sig := range cniSignatures {
				for _, h := range sig.ImageHint {
					if strings.Contains(img, strings.ToLower(h)) && !seen[sig.Name] {
						seen[sig.Name] = true
						sev := scanner.SevInfo
						if sig.KnownIssues != "" {
							sev = scanner.SevLow
						}
						out = append(out, scanner.Finding{
							RuleID:   "KH-NET-010",
							Category: scanner.CatCNI,
							Severity: sev,
							Title:    fmt.Sprintf("CNI plugin detected: %s", sig.Name),
							Description: fmt.Sprintf("Cluster is running %s (namespace hint: %s). Each CNI has its own NetworkPolicy nuances. %s",
								sig.Name, sig.NSHint, sig.KnownIssues),
							Resource: scanner.Resource{Kind: "Cluster", Name: sig.Name},
							Evidence: fmt.Sprintf("pod %s/%s image=%s", p.Namespace, p.Name, img),
							Tags:     []string{"cni", strings.ToLower(strings.ReplaceAll(sig.Name, " ", "-"))},
						})
					}
				}
			}
		}
	}
	return out
}

func npBypassDetect(inv *scanner.Inventory) []scanner.Finding {
	npByNS := map[string][]netv1.NetworkPolicy{}
	for _, np := range inv.NetworkPolicies {
		npByNS[np.Namespace] = append(npByNS[np.Namespace], np)
	}

	var out []scanner.Finding
	for ns, policies := range npByNS {

		for _, p := range inv.Pods {
			if p.Namespace != ns {
				continue
			}
			matched := 0
			for _, np := range policies {
				if labelSelectorMatches(np.Spec.PodSelector.MatchLabels, p.Labels) {
					matched++
				}
			}
			if matched == 0 {
				out = append(out, scanner.Finding{
					RuleID:   "KH-NET-011",
					Category: scanner.CatCNI,
					Severity: scanner.SevMedium,
					Title:    fmt.Sprintf("Pod %s/%s is in a policed namespace but NO NetworkPolicy selects it", ns, p.Name),
					Description: fmt.Sprintf("Namespace %q has %d NetworkPolicies, but this pod isn't selected by any of them. The default K8s semantic is: if NO policy selects a pod, ingress is ALLOWED from everywhere. An attacker on another pod in this namespace has an unconstrained path to this pod.",
						ns, len(policies)),
					Resource:       scanner.Resource{Kind: "Pod", Namespace: ns, Name: p.Name},
					Evidence:       fmt.Sprintf("labels=%v; %d NP(s) exist in ns, 0 match", p.Labels, len(policies)),
					Impact:         "Lateral movement path inside the namespace.",
					Recommendation: "Add a default-deny NetworkPolicy scoped to the whole namespace and allow only the traffic you need.",
					Tags:           []string{"cni", "np-bypass"},
				})
			}
		}
	}
	return out
}

func labelSelectorMatches(sel, labels map[string]string) bool {
	if len(sel) == 0 {

		return true
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func dnsPoisonEnabler(inv *scanner.Inventory) []scanner.Finding {

	var out []scanner.Finding
	checkRule := func(holder string, verbs, resources []string, ns string) {
		hasPatch := contains(verbs, "patch") || contains(verbs, "update") || contains(verbs, "*")
		hasCM := contains(resources, "configmaps") || contains(resources, "*")
		if !(hasPatch && hasCM) {
			return
		}
		if ns != "" && ns != "kube-system" {
			return
		}
		out = append(out, scanner.Finding{
			RuleID:         "KH-NET-012",
			Category:       scanner.CatCNI,
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("DNS-poisoning enabler: %s can patch configmaps in kube-system", holder),
			Description:    "This role lets an attacker modify the CoreDNS or kube-dns ConfigMap. The next coredns rollout picks up the poisoned Corefile and every in-cluster DNS query for arbitrary names can be redirected to an attacker pod. The scanner does NOT poison DNS — this is a statics rule.",
			Resource:       scanner.Resource{Kind: "Role/ClusterRole", Name: holder},
			Evidence:       fmt.Sprintf("verbs=%v resources=%v ns=%s", verbs, resources, ns),
			Impact:         "Credential phishing for every workload (oauth redirect URIs, IdP, etc.); cluster-wide MITM.",
			Recommendation: "Forbid patch on configmaps in kube-system except for the CoreDNS deployment's own SA.",
			Tags:           []string{"cni", "dns-poisoning"},
		})
	}
	for _, cr := range inv.ClusterRoles {
		for _, r := range cr.Rules {
			checkRule("ClusterRole/"+cr.Name, r.Verbs, r.Resources, "")
		}
	}
	for _, r := range inv.Roles {
		for _, rule := range r.Rules {
			checkRule(fmt.Sprintf("Role/%s/%s", r.Namespace, r.Name), rule.Verbs, rule.Resources, r.Namespace)
		}
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
