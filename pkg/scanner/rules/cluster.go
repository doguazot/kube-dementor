package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func ClusterRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-CLU-001", Title: "Outdated Kubernetes version", Category: scanner.CatClusterLevel, Fn: ruleCLU001Version},
		{ID: "KH-CLU-002", Title: "Namespace missing Pod Security Admission label", Category: scanner.CatClusterLevel, Fn: ruleCLU002PSA},
		{ID: "KH-CLU-003", Title: "Control-plane component found on worker node", Category: scanner.CatClusterLevel, Fn: ruleCLU003CPLeak},
	}
}

const minSupportedMinor = 28

func ruleCLU001Version(_ *scanner.Inventory, sess *kubectx.Session) []scanner.Finding {
	v := sess.Info.ServerVersion
	if v == "" {
		return nil
	}
	if !strings.HasPrefix(v, "v1.") {
		return nil
	}
	parts := strings.SplitN(strings.TrimPrefix(v, "v1."), ".", 2)
	minor := 0
	for _, ch := range parts[0] {
		if ch >= '0' && ch <= '9' {
			minor = minor*10 + int(ch-'0')
		} else {
			break
		}
	}
	if minor == 0 || minor >= minSupportedMinor {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevMedium,
		Title:          "Kubernetes version out of upstream support",
		Description:    fmt.Sprintf("Cluster is running %s; upstream support covers only the three most recent minor releases.", v),
		Resource:       scanner.Resource{Kind: "Cluster", Name: sess.Info.ClusterName},
		Recommendation: "Plan an upgrade to a supported minor version to continue receiving security fixes.",
		Tags:           []string{"cluster", "patching"},
	}}
}

func ruleCLU002PSA(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, ns := range inv.Namespaces {
		if systemNamespaces[ns.Name] {
			continue
		}
		enforce := ns.Labels["pod-security.kubernetes.io/enforce"]
		if enforce == "baseline" || enforce == "restricted" {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevLow,
			Title:          "Namespace without Pod Security Admission enforce label",
			Description:    fmt.Sprintf("Namespace %q does not set pod-security.kubernetes.io/enforce=baseline|restricted.", ns.Name),
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns.Name},
			Recommendation: "Label each application namespace with pod-security.kubernetes.io/enforce=restricted (plus warn/audit labels).",
			RemediationCmd: fmt.Sprintf("kubectl label ns %s pod-security.kubernetes.io/enforce=restricted --overwrite", ns.Name),
			Tags:           []string{"cluster", "psa"},
		})
	}
	return out
}

func ruleCLU003CPLeak(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	cpNodes := map[string]bool{}
	for _, n := range inv.Nodes {
		if _, ok := n.Labels["node-role.kubernetes.io/control-plane"]; ok {
			cpNodes[n.Name] = true
		}
		if _, ok := n.Labels["node-role.kubernetes.io/master"]; ok {
			cpNodes[n.Name] = true
		}
	}
	cpComponentHints := []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd"}
	for _, p := range inv.Pods {
		if p.Spec.NodeName == "" {
			continue
		}
		for _, hint := range cpComponentHints {
			if strings.Contains(p.Name, hint) && !cpNodes[p.Spec.NodeName] {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevMedium,
					Title:          "Control-plane component running on worker node",
					Description:    fmt.Sprintf("Pod %s/%s looks like a control-plane component (%s) but is scheduled on node %q which is not labelled control-plane.", p.Namespace, p.Name, hint, p.Spec.NodeName),
					Resource:       podResource(p),
					Recommendation: "Restrict control-plane components to control-plane nodes via nodeSelector/tolerations.",
					Tags:           []string{"cluster", "topology"},
				})
				break
			}
		}
	}
	return out
}
