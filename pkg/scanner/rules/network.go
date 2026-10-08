package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
)

func NetworkRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-NET-001", Title: "Namespace has no NetworkPolicy", Category: scanner.CatNetwork, Fn: ruleNET001NoNetPol},
		{ID: "KH-NET-002", Title: "Service of type LoadBalancer without restrictions", Category: scanner.CatNetwork, Fn: ruleNET002LoadBalancer},
		{ID: "KH-NET-003", Title: "NodePort service exposes internal application", Category: scanner.CatNetwork, Fn: ruleNET003NodePort},
		{ID: "KH-NET-004", Title: "Sensitive Kubernetes dashboard exposed", Category: scanner.CatNetwork, Fn: ruleNET004Dashboard},
	}
}

var systemNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
}

func ruleNET001NoNetPol(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	nsWithPol := map[string]bool{}
	for _, p := range inv.NetworkPolicies {
		nsWithPol[p.Namespace] = true
	}
	var out []scanner.Finding
	for _, ns := range inv.Namespaces {
		if systemNamespaces[ns.Name] {
			continue
		}
		if nsWithPol[ns.Name] {
			continue
		}

		hasPod := false
		for _, p := range inv.Pods {
			if p.Namespace == ns.Name {
				hasPod = true
				break
			}
		}
		if !hasPod {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          "Namespace has no NetworkPolicy",
			Description:    fmt.Sprintf("Namespace %q has active pods but no NetworkPolicy; all pod-to-pod traffic is unrestricted.", ns.Name),
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns.Name},
			Impact:         "An attacker with RCE in any pod can freely scan and attack other pods/services across namespaces.",
			Recommendation: "Add a default-deny ingress/egress NetworkPolicy and explicitly allow required flows.",
			RemediationYAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]`, ns.Name),
			Tags: []string{"network", "segmentation"},
		})
	}
	return out
}

func ruleNET002LoadBalancer(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Services {
		if s.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		if len(s.Spec.LoadBalancerSourceRanges) > 0 {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          "LoadBalancer Service without sourceRanges",
			Description:    fmt.Sprintf("Service %s/%s is type=LoadBalancer with no loadBalancerSourceRanges — exposed to the entire Internet.", s.Namespace, s.Name),
			Resource:       scanner.Resource{Kind: "Service", Namespace: s.Namespace, Name: s.Name},
			Recommendation: "Set spec.loadBalancerSourceRanges to your trusted IP ranges or front with a WAF/ingress.",
			Tags:           []string{"network", "exposure"},
		})
	}
	return out
}

func ruleNET003NodePort(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Services {
		if s.Spec.Type != corev1.ServiceTypeNodePort {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevLow,
			Title:          "NodePort Service in use",
			Description:    fmt.Sprintf("Service %s/%s is type=NodePort; anyone who can reach the node IPs on the allocated port can reach the service.", s.Namespace, s.Name),
			Resource:       scanner.Resource{Kind: "Service", Namespace: s.Namespace, Name: s.Name},
			Recommendation: "Prefer ClusterIP with an Ingress controller or a LoadBalancer with sourceRanges.",
			Tags:           []string{"network", "exposure"},
		})
	}
	return out
}

func ruleNET004Dashboard(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Services {
		if !strings.Contains(strings.ToLower(s.Name), "kubernetes-dashboard") {
			continue
		}
		if s.Spec.Type == corev1.ServiceTypeClusterIP {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevHigh,
			Title:          "Kubernetes Dashboard exposed via " + string(s.Spec.Type),
			Description:    fmt.Sprintf("Service %s/%s is of type %s.", s.Namespace, s.Name, s.Spec.Type),
			Resource:       scanner.Resource{Kind: "Service", Namespace: s.Namespace, Name: s.Name},
			Impact:         "Historically the #1 Kubernetes intrusion vector. Even with auth enabled, dashboard bugs and misconfigurations have led to many compromises.",
			Recommendation: "Switch to ClusterIP, require auth with OIDC/LDAP, and put behind a VPN + ingress.",
			Tags:           []string{"network", "dashboard"},
		})
	}
	return out
}
