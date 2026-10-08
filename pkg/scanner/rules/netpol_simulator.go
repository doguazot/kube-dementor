package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
)

func NetPolSimulatorRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-NETPOL-NO-DEFAULT-DENY-ING", Title: "Namespace has no default-deny *ingress* baseline", Category: scanner.CatNetwork, Fn: ruleNetPolNoDefaultDenyIngress},
		{ID: "KH-NETPOL-NO-DEFAULT-DENY-EGR", Title: "Namespace has no default-deny *egress* baseline", Category: scanner.CatNetwork, Fn: ruleNetPolNoDefaultDenyEgress},
		{ID: "KH-NETPOL-CROSS-NS-OPEN", Title: "Pod is reachable from every namespace (namespaceSelector: {})", Category: scanner.CatNetwork, Fn: ruleNetPolCrossNSOpen},
		{ID: "KH-NETPOL-EGRESS-INTERNET", Title: "Pod has unrestricted egress to the internet (no IP block / 0.0.0.0/0 with no IMDS exception)", Category: scanner.CatNetwork, Fn: ruleNetPolEgressInternet},
		{ID: "KH-NETPOL-IMDS-NOT-BLOCKED", Title: "Egress rules do not exclude cloud-metadata IPs (169.254.169.254)", Category: scanner.CatNetwork, Fn: ruleNetPolIMDSNotBlocked},
		{ID: "KH-NETPOL-DNS-OPEN", Title: "Egress allows DNS to anywhere (potential exfil channel)", Category: scanner.CatNetwork, Fn: ruleNetPolDNSOpen},
	}
}

func nsHasDefaultDenyIngress(ns string, polices []netv1.NetworkPolicy) bool {
	for _, p := range polices {
		if p.Namespace != ns {
			continue
		}
		if len(p.Spec.PodSelector.MatchLabels) > 0 || len(p.Spec.PodSelector.MatchExpressions) > 0 {
			continue
		}

		hasIngress := false
		for _, t := range p.Spec.PolicyTypes {
			if t == netv1.PolicyTypeIngress {
				hasIngress = true
			}
		}
		if hasIngress && len(p.Spec.Ingress) == 0 {
			return true
		}
	}
	return false
}

func nsHasDefaultDenyEgress(ns string, polices []netv1.NetworkPolicy) bool {
	for _, p := range polices {
		if p.Namespace != ns {
			continue
		}
		if len(p.Spec.PodSelector.MatchLabels) > 0 || len(p.Spec.PodSelector.MatchExpressions) > 0 {
			continue
		}
		hasEgress := false
		for _, t := range p.Spec.PolicyTypes {
			if t == netv1.PolicyTypeEgress {
				hasEgress = true
			}
		}
		if hasEgress && len(p.Spec.Egress) == 0 {
			return true
		}
	}
	return false
}

func peerMatchesAllNamespaces(p netv1.NetworkPolicyPeer) bool {
	if p.NamespaceSelector == nil {
		return false
	}
	if len(p.NamespaceSelector.MatchLabels) == 0 && len(p.NamespaceSelector.MatchExpressions) == 0 {
		return true
	}
	return false
}

func peerMatchesAllPods(p netv1.NetworkPolicyPeer) bool {
	if p.PodSelector == nil {
		return true
	}
	return len(p.PodSelector.MatchLabels) == 0 && len(p.PodSelector.MatchExpressions) == 0
}

func peerIsOpenInternet(p netv1.NetworkPolicyPeer) bool {
	if p.IPBlock == nil {
		return false
	}
	if p.IPBlock.CIDR != "0.0.0.0/0" && p.IPBlock.CIDR != "::/0" {
		return false
	}
	hasIMDSExcept := false
	for _, ex := range p.IPBlock.Except {
		if strings.HasPrefix(ex, "169.254.169.254") || ex == "169.254.169.254/32" {
			hasIMDSExcept = true
		}
	}
	return !hasIMDSExcept
}

func ruleNetPolNoDefaultDenyIngress(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	if len(inv.NetworkPolicies) == 0 && len(inv.Namespaces) == 0 {
		return nil
	}
	var out []scanner.Finding
	for _, ns := range inv.Namespaces {
		if shouldSkipNs(ns.Name) {
			continue
		}
		if nsHasDefaultDenyIngress(ns.Name, inv.NetworkPolicies) {
			continue
		}

		hasPods := false
		for _, p := range inv.Pods {
			if p.Namespace == ns.Name {
				hasPods = true
				break
			}
		}
		if !hasPods {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("Namespace %q has no default-deny ingress baseline", ns.Name),
			Description:    "Without a `podSelector:{}` + `policyTypes:[Ingress]` + empty ingress NetworkPolicy, every pod in this namespace is reachable by default from any other pod that has a NetworkPolicy that allows it (or from any pod at all if the destination has no policy). The intuitive Kubernetes default is *open*.",
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns.Name},
			Evidence:       fmt.Sprintf("namespace=%s netpol-count=%d", ns.Name, countNsPolicies(ns.Name, inv.NetworkPolicies)),
			Impact:         "Lateral-movement: any compromised pod in another namespace can talk to anything here as long as its own egress isn't blocked.",
			Recommendation: "Apply a default-deny ingress NetworkPolicy and then allowlist what the workloads actually need:\n\n```yaml\nkind: NetworkPolicy\nmetadata: { name: default-deny, namespace: " + ns.Name + " }\nspec:\n  podSelector: {}\n  policyTypes: [Ingress]\n```",
			Tags:           []string{"network", "policy", "default-deny"},
		})
	}
	return out
}

func ruleNetPolNoDefaultDenyEgress(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, ns := range inv.Namespaces {
		if shouldSkipNs(ns.Name) {
			continue
		}
		if nsHasDefaultDenyEgress(ns.Name, inv.NetworkPolicies) {
			continue
		}
		hasPods := false
		for _, p := range inv.Pods {
			if p.Namespace == ns.Name {
				hasPods = true
				break
			}
		}
		if !hasPods {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("Namespace %q has no default-deny egress baseline", ns.Name),
			Description:    "A pod can reach any external service (DNS, HTTP, raw TCP) and any pod in any namespace. Lack of egress restriction is the most common reason post-exploit C2 succeeds.",
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns.Name},
			Evidence:       fmt.Sprintf("namespace=%s netpol-count=%d", ns.Name, countNsPolicies(ns.Name, inv.NetworkPolicies)),
			Impact:         "Compromised pods can exfil data and reach C2 over arbitrary protocols. Attackers prefer DNS-over-HTTPS to bypass network logging.",
			Recommendation: "Add a default-deny egress policy and then allowlist DNS (kube-dns), the API server (if needed), and named external services.",
			Tags:           []string{"network", "policy", "egress"},
		})
	}
	return out
}

func ruleNetPolCrossNSOpen(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.NetworkPolicies {
		for _, ing := range p.Spec.Ingress {
			for _, peer := range ing.From {
				if !peerMatchesAllNamespaces(peer) {
					continue
				}
				if !peerMatchesAllPods(peer) {

				}
				out = append(out, scanner.Finding{
					Severity:       scanner.SevMedium,
					Title:          fmt.Sprintf("NetworkPolicy %s/%s allows ingress from every namespace", p.Namespace, p.Name),
					Description:    "A `namespaceSelector: {}` peer with no podSelector is the network-policy way of saying 'anything in this cluster'. The pods this policy targets effectively have no inter-namespace boundary.",
					Resource:       scanner.Resource{Kind: "NetworkPolicy", Namespace: p.Namespace, Name: p.Name},
					Evidence:       fmt.Sprintf("targetSelector=%v peer=namespaceSelector:{}", p.Spec.PodSelector),
					Impact:         "Lateral movement: any compromised pod cluster-wide can talk to the protected workload.",
					Recommendation: "Replace `namespaceSelector: {}` with explicit namespace labels (e.g. `kubernetes.io/metadata.name: monitoring`) or use a podSelector to scope the source pods.",
					Tags:           []string{"network", "policy", "cross-ns"},
				})
			}
		}
	}
	return out
}

func ruleNetPolEgressInternet(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.NetworkPolicies {
		for _, eg := range p.Spec.Egress {
			for _, peer := range eg.To {
				if !peerIsOpenInternet(peer) {
					continue
				}
				out = append(out, scanner.Finding{
					Severity:       scanner.SevHigh,
					Title:          fmt.Sprintf("NetworkPolicy %s/%s allows egress to 0.0.0.0/0 without IMDS exception", p.Namespace, p.Name),
					Description:    "Egress rule with `ipBlock: 0.0.0.0/0` permits the pod to reach any IPv4 destination — including the cloud metadata service at 169.254.169.254 which is the typical credential-theft target.",
					Resource:       scanner.Resource{Kind: "NetworkPolicy", Namespace: p.Namespace, Name: p.Name},
					Evidence:       fmt.Sprintf("egress allows %s except=%v", peer.IPBlock.CIDR, peer.IPBlock.Except),
					Impact:         "Compromised pod can phone home to attacker C2 + steal cloud credentials from IMDS in one step.",
					Recommendation: "Either restrict egress to named destinations or add `except: [169.254.169.254/32, 169.254.0.0/16, 192.168.0.0/16, 10.0.0.0/8]` to the ipBlock.",
					Tags:           []string{"network", "policy", "egress", "imds"},
				})
			}
		}
	}
	return out
}

func ruleNetPolIMDSNotBlocked(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding

	byNS := map[string]bool{}
	for _, p := range inv.NetworkPolicies {
		for _, t := range p.Spec.PolicyTypes {
			if t == netv1.PolicyTypeEgress {
				byNS[p.Namespace] = true
			}
		}
	}
	for ns, hasEg := range byNS {
		if !hasEg {
			continue
		}
		blocked := false
		for _, p := range inv.NetworkPolicies {
			if p.Namespace != ns {
				continue
			}
			for _, eg := range p.Spec.Egress {
				for _, peer := range eg.To {
					if peer.IPBlock != nil {
						for _, ex := range peer.IPBlock.Except {
							if ex == "169.254.169.254/32" || strings.HasPrefix(ex, "169.254.169.254") {
								blocked = true
							}
						}
					}
				}
			}
		}
		if blocked {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("Namespace %q has egress policies but none excludes the cloud metadata IP", ns),
			Description:    "Egress restrictions exist but 169.254.169.254 is not excluded. On AWS/GCP/Azure that IP serves IMDS and exposes the node's IAM credentials. A compromised pod that beats the existing egress rules (e.g. via allowed DNS) can still attempt to fetch IMDS.",
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns},
			Evidence:       fmt.Sprintf("namespace=%s egress-policies=present, IMDS-block=missing", ns),
			Impact:         "Cloud-credential theft despite NetworkPolicy.",
			Recommendation: "Add an explicit deny for 169.254.169.254/32 in every egress NetworkPolicy or use IMDSv2 + `hop-limit=1` on the node so containers can't reach it.",
			Tags:           []string{"network", "policy", "imds"},
		})
	}
	return out
}

func ruleNetPolDNSOpen(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.NetworkPolicies {
		for _, eg := range p.Spec.Egress {
			isDNS := false
			for _, port := range eg.Ports {
				if port.Port == nil {
					continue
				}
				if port.Port.IntValue() == 53 {
					isDNS = true
				}
			}
			if !isDNS {
				continue
			}
			for _, peer := range eg.To {
				if peerIsOpenInternet(peer) {
					out = append(out, scanner.Finding{
						Severity:       scanner.SevMedium,
						Title:          fmt.Sprintf("NetworkPolicy %s/%s allows DNS (port 53) to the entire internet", p.Namespace, p.Name),
						Description:    "DNS to 0.0.0.0/0 is a textbook exfiltration channel: long subdomains carry base64-encoded data; the request is logged at most as 'DNS query' which security teams rarely inspect.",
						Resource:       scanner.Resource{Kind: "NetworkPolicy", Namespace: p.Namespace, Name: p.Name},
						Evidence:       "egress port=53 to=0.0.0.0/0",
						Impact:         "DNS-based exfil bypasses most egress monitoring.",
						Recommendation: "Restrict DNS egress to your in-cluster CoreDNS Service (kube-dns) only.",
						Tags:           []string{"network", "policy", "dns", "exfil"},
					})
				}
			}
		}
	}
	return out
}

func shouldSkipNs(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

func countNsPolicies(ns string, polices []netv1.NetworkPolicy) int {
	c := 0
	for _, p := range polices {
		if p.Namespace == ns {
			c++
		}
	}
	return c
}

var _ = corev1.PodSpec{}
