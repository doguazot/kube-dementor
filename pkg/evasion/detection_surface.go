package evasion

import (
	"context"
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type EDRSignature struct {
	Name          string
	Vendor        string
	NamespaceKey  string
	DaemonSetKey  string
	ImageKeywords []string
	NoiseBudget   string
	Notes         string
}

var edrSignatures = []EDRSignature{
	{
		Name: "Falco", Vendor: "Sysdig / CNCF",
		NamespaceKey: "falco", DaemonSetKey: "falco",
		ImageKeywords: []string{"falcosecurity/falco", "falco:"},
		NoiseBudget:   "aggressive",
		Notes:         "Kernel-level syscall monitor. Detects exec, shell-in-container, package-manager-in-container, sensitive-mount.",
	},
	{
		Name: "Tetragon", Vendor: "Isovalent",
		NamespaceKey: "tetragon", DaemonSetKey: "tetragon",
		ImageKeywords: []string{"cilium/tetragon"},
		NoiseBudget:   "aggressive",
		Notes:         "eBPF observability + policy enforcer. Sees every exec/open/connect syscall.",
	},
	{
		Name: "Sysdig Agent", Vendor: "Sysdig",
		NamespaceKey: "sysdig", DaemonSetKey: "sysdig-agent",
		ImageKeywords: []string{"sysdig/agent", "quay.io/sysdig"},
		NoiseBudget:   "aggressive",
	},
	{
		Name: "StackRox / Red Hat ACS", Vendor: "Red Hat",
		NamespaceKey: "stackrox", DaemonSetKey: "collector",
		ImageKeywords: []string{"stackrox.io/collector", "stackrox/collector"},
		NoiseBudget:   "aggressive",
	},
	{
		Name: "Aqua Enforcer", Vendor: "Aqua Security",
		NamespaceKey: "aqua", DaemonSetKey: "aqua-enforcer",
		ImageKeywords: []string{"registry.aquasec.com/enforcer", "aquasec/enforcer"},
		NoiseBudget:   "aggressive",
	},
	{
		Name: "Cilium Hubble", Vendor: "Isovalent",
		NamespaceKey: "cilium", DaemonSetKey: "hubble",
		ImageKeywords: []string{"cilium/hubble"},
		NoiseBudget:   "medium",
		Notes:         "Network observability; sees every flow, not syscalls.",
	},
	{
		Name: "Trivy Operator", Vendor: "Aqua Security",
		NamespaceKey: "trivy-system", DaemonSetKey: "trivy-operator",
		ImageKeywords: []string{"aquasec/trivy-operator"},
		NoiseBudget:   "light",
		Notes:         "Scheduled vulnerability scanner; won't catch live attacks.",
	},
	{
		Name: "Calico Enterprise / Tigera", Vendor: "Tigera",
		NamespaceKey: "calico-system", DaemonSetKey: "calico-node",
		ImageKeywords: []string{"calico/enterprise", "tigera/"},
		NoiseBudget:   "medium",
	},
	{
		Name: "Datadog Agent", Vendor: "Datadog",
		NamespaceKey: "datadog", DaemonSetKey: "datadog",
		ImageKeywords: []string{"gcr.io/datadoghq", "datadog/agent"},
		NoiseBudget:   "medium",
	},
	{
		Name: "Sysdig Secure", Vendor: "Sysdig",
		NamespaceKey: "sysdig-agent", DaemonSetKey: "",
		ImageKeywords: []string{"sysdig/secure-light"},
		NoiseBudget:   "aggressive",
	},
}

type DetectionSurface struct {
	EDRs        []DetectedEDR
	Worst       string
	TotalWeight int
}

type DetectedEDR struct {
	Signature EDRSignature
	Evidence  string
}

func Scan(_ context.Context, _ *kubectx.Session, inv *scanner.Inventory) (*DetectionSurface, []scanner.Finding) {
	surface := &DetectionSurface{Worst: "none"}
	var out []scanner.Finding

	nsSet := map[string]bool{}
	for _, n := range inv.Namespaces {
		nsSet[strings.ToLower(n.Name)] = true
	}

	imageSet := map[string]bool{}
	for _, p := range inv.Pods {
		for _, c := range append(p.Spec.Containers, p.Spec.InitContainers...) {
			imageSet[strings.ToLower(c.Image)] = true
		}
	}

	for _, sig := range edrSignatures {
		matched := false
		var evidence []string
		if sig.NamespaceKey != "" {
			for ns := range nsSet {
				if strings.Contains(ns, sig.NamespaceKey) {
					matched = true
					evidence = append(evidence, "ns="+ns)
					break
				}
			}
		}
		if !matched {
			for img := range imageSet {
				for _, kw := range sig.ImageKeywords {
					if strings.Contains(img, strings.ToLower(kw)) {
						matched = true
						evidence = append(evidence, "image="+img)
						break
					}
				}
				if matched {
					break
				}
			}
		}
		if matched {
			surface.EDRs = append(surface.EDRs, DetectedEDR{Signature: sig, Evidence: strings.Join(evidence, ", ")})
			surface.TotalWeight += noiseWeight(sig.NoiseBudget)
			if noiseWorse(sig.NoiseBudget, surface.Worst) {
				surface.Worst = sig.NoiseBudget
			}

			out = append(out, scanner.Finding{
				RuleID:   "KH-EVA-001",
				Category: scanner.CatEvasion,
				Severity: scanner.SevInfo,
				Title:    fmt.Sprintf("Runtime security tool detected: %s", sig.Name),
				Description: fmt.Sprintf("%s (vendor: %s) is deployed in this cluster and likely to observe exec/open/connect syscalls from any pod where the scanner or an attacker drops a shell. Noise budget: %s.",
					sig.Name, sig.Vendor, sig.NoiseBudget),
				Resource:       scanner.Resource{Kind: "Cluster", Name: sig.Name},
				Evidence:       strings.Join(evidence, ", "),
				Impact:         "Active exploitation may generate alerts. Plan the engagement window with the SOC.",
				Recommendation: "During authorised red-team testing, coordinate with the team running " + sig.Name + " to get a controlled detection baseline.",
				Tags:           []string{"evasion", "edr", strings.ToLower(sig.Name)},
			})
		}
	}
	return surface, out
}

func noiseWeight(b string) int {
	switch b {
	case "aggressive":
		return 3
	case "medium":
		return 2
	case "light":
		return 1
	}
	return 0
}
func noiseWorse(a, b string) bool { return noiseWeight(a) > noiseWeight(b) }
