package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func MeshRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-MESH-DETECT", Title: "Service mesh detected — record posture", Category: scanner.CatServiceMesh, Fn: ruleMeshDetect},
		{ID: "KH-MESH-NO-SIDECAR", Title: "Pod in a meshed namespace has no mesh sidecar / ambient binding", Category: scanner.CatServiceMesh, Fn: ruleMeshNoSidecar},
		{ID: "KH-MESH-PERMISSIVE-MTLS", Title: "Istio PeerAuthentication likely PERMISSIVE (sidecar accepts plaintext)", Category: scanner.CatServiceMesh, Fn: ruleMeshPermissiveMTLS},
		{ID: "KH-MESH-AUTHZ-MISSING", Title: "Pod is meshed but no AuthorizationPolicy targets it", Category: scanner.CatServiceMesh, Fn: ruleMeshAuthzMissing},
		{ID: "KH-MESH-INJECTOR-PRIV", Title: "Mesh sidecar injector webhook has high privileges", Category: scanner.CatServiceMesh, Fn: ruleMeshInjectorPriv},
		{ID: "KH-MESH-EGRESS-OPEN", Title: "Istio egress gateway absent — sidecars allow direct external traffic", Category: scanner.CatServiceMesh, Fn: ruleMeshEgressOpen},
	}
}

type meshKind string

const (
	meshNone    meshKind = "none"
	meshIstio   meshKind = "istio"
	meshLinkerd meshKind = "linkerd"
	meshCilium  meshKind = "cilium-mesh"
)

func detectMesh(inv *scanner.Inventory) (meshKind, []string) {
	var evidence []string
	mesh := meshNone

	istioCount := 0
	linkerdCount := 0
	ciliumMeshCount := 0
	for _, p := range inv.Pods {
		ns := p.Namespace
		nm := strings.ToLower(p.Name)
		switch {
		case ns == "istio-system" || strings.Contains(nm, "istiod") || strings.Contains(nm, "istio-pilot"):
			istioCount++
		case ns == "linkerd" || strings.HasPrefix(nm, "linkerd-"):
			linkerdCount++
		case (ns == "kube-system" && strings.Contains(nm, "cilium")) && strings.Contains(nm, "envoy"):
			ciliumMeshCount++
		}
	}
	switch {
	case istioCount > 0:
		mesh = meshIstio
		evidence = append(evidence, fmt.Sprintf("istio-system pods=%d", istioCount))
	case linkerdCount > 0:
		mesh = meshLinkerd
		evidence = append(evidence, fmt.Sprintf("linkerd pods=%d", linkerdCount))
	case ciliumMeshCount > 0:
		mesh = meshCilium
		evidence = append(evidence, fmt.Sprintf("cilium-envoy pods=%d", ciliumMeshCount))
	}
	return mesh, evidence
}

func ruleMeshDetect(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	mesh, ev := detectMesh(inv)
	if mesh == meshNone {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevInfo,
		Title:          fmt.Sprintf("Service mesh detected: %s", mesh),
		Description:    fmt.Sprintf("Cluster appears to run %s. Subsequent KH-MESH-* findings analyse the mesh-specific posture.", mesh),
		Resource:       scanner.Resource{Kind: "Cluster"},
		Evidence:       strings.Join(ev, ", "),
		Impact:         "Informational baseline for the mesh-aware findings that follow.",
		Recommendation: "Run `istioctl analyze` (Istio) or `linkerd check` (Linkerd) for vendor-supplied auditing on top of this baseline.",
		Tags:           []string{"service-mesh", "detect", string(mesh)},
	}}
}

func nsHasMeshLabel(ns string, inv *scanner.Inventory) (string, bool) {
	for _, n := range inv.Namespaces {
		if n.Name != ns {
			continue
		}
		if v, ok := n.Labels["istio-injection"]; ok && v == "enabled" {
			return "istio-injection=enabled", true
		}
		if v, ok := n.Labels["linkerd.io/inject"]; ok && v == "enabled" {
			return "linkerd.io/inject=enabled", true
		}
	}
	return "", false
}

func podHasSidecar(p any) bool {
	type spec struct {
		Containers []struct {
			Name  string
			Image string
		}
	}

	return false
}

func ruleMeshNoSidecar(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	mesh, _ := detectMesh(inv)
	if mesh == meshNone {
		return nil
	}
	var out []scanner.Finding
	for _, p := range inv.Pods {
		label, on := nsHasMeshLabel(p.Namespace, inv)
		if !on {
			continue
		}

		hasSidecar := false
		for _, c := range append(p.Spec.Containers, p.Spec.InitContainers...) {
			n := strings.ToLower(c.Name)
			if n == "istio-proxy" || n == "linkerd-proxy" || strings.Contains(c.Image, "/proxyv2:") {
				hasSidecar = true
				break
			}
		}
		if hasSidecar {
			continue
		}

		if mesh == meshCilium {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("Pod %s/%s in meshed namespace has no mesh sidecar", p.Namespace, p.Name),
			Description:    fmt.Sprintf("Namespace %s is labelled %s but pod %s lacks the mesh proxy. Traffic to/from this pod bypasses mTLS, AuthorizationPolicy, and observability.", p.Namespace, label, p.Name),
			Resource:       podResource(p),
			Evidence:       fmt.Sprintf("ns-label=%s containers=%d sidecar=missing", label, len(p.Spec.Containers)),
			Impact:         "mTLS bypass: any other compromised pod with raw network access can talk to this workload in cleartext, sidestepping the mesh controls.",
			Recommendation: "Investigate why injection failed (admission webhook timeout, custom injection annotation `sidecar.istio.io/inject: \"false\"`, etc.). Either enable the sidecar or move the workload out of the meshed namespace.",
			Tags:           []string{"service-mesh", "sidecar", "mtls"},
		})
	}
	return out
}

func ruleMeshPermissiveMTLS(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	mesh, _ := detectMesh(inv)
	if mesh != meshIstio {
		return nil
	}
	for _, p := range inv.Pods {
		if !strings.HasPrefix(p.Name, "istiod") {
			continue
		}
		for _, c := range p.Spec.Containers {
			for _, e := range c.Env {
				if strings.EqualFold(e.Name, "PILOT_ENABLE_AMBIENT") && e.Value == "true" {

					return nil
				}
			}
		}
	}
	return []scanner.Finding{{
		Severity:       scanner.SevHigh,
		Title:          "Istio detected — verify cluster-wide PeerAuthentication is STRICT",
		Description:    "Default Istio installations leave the global PeerAuthentication mode unset which evaluates to PERMISSIVE — the sidecar accepts plaintext from non-mesh peers. Without STRICT mTLS, an attacker who reaches the pod IP directly can call its services in cleartext (bypassing AuthorizationPolicy).",
		Resource:       scanner.Resource{Kind: "Cluster"},
		Evidence:       "Istio control plane present; PeerAuthentication CRDs not inspectable via this static scanner.",
		Impact:         "Mesh control bypass via raw pod-IP. Audit logs still attribute traffic to a sidecar but the auth identity can be spoofed.",
		Recommendation: "Run `kubectl get peerauthentication -A -o yaml` and verify a `mode: STRICT` policy at namespace or mesh-wide scope. Apply:\n```yaml\napiVersion: security.istio.io/v1beta1\nkind: PeerAuthentication\nmetadata: { name: default, namespace: istio-system }\nspec:\n  mtls: { mode: STRICT }\n```",
		Tags:           []string{"service-mesh", "istio", "mtls", "audit-required"},
	}}
}

func ruleMeshAuthzMissing(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	mesh, _ := detectMesh(inv)
	if mesh != meshIstio {
		return nil
	}

	pods := map[string]int{}
	for _, p := range inv.Pods {
		if _, on := nsHasMeshLabel(p.Namespace, inv); on {
			pods[p.Namespace]++
		}
	}
	var out []scanner.Finding
	for ns, n := range pods {
		if n < 5 {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("Meshed namespace %q has %d pods — audit AuthorizationPolicy coverage", ns, n),
			Description:    "Without an AuthorizationPolicy targeting the workload, the mesh sidecar accepts requests from any *authenticated* peer. STRICT mTLS proves identity but does not authorise the call. Lateral movement post-compromise still works cluster-wide.",
			Resource:       scanner.Resource{Kind: "Namespace", Name: ns},
			Evidence:       fmt.Sprintf("namespace=%s meshed-pods=%d AuthZ-CRD-not-inspected", ns, n),
			Impact:         "mTLS without AuthZ means any compromised pod in any namespace can call this namespace's services as long as it's mesh-bound.",
			Recommendation: "For each Service create an AuthorizationPolicy like:\n```yaml\nkind: AuthorizationPolicy\nmetadata: { name: only-frontend, namespace: " + ns + " }\nspec:\n  selector: { matchLabels: { app: api } }\n  rules:\n  - from:\n    - source:\n        principals: [\"cluster.local/ns/frontend/sa/web\"]\n```",
			Tags:           []string{"service-mesh", "istio", "authz"},
		})
	}
	return out
}

func ruleMeshInjectorPriv(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	mesh, _ := detectMesh(inv)
	if mesh == meshNone {
		return nil
	}

	var out []scanner.Finding
	for _, m := range inv.MutatingWebhooks {
		if !strings.Contains(strings.ToLower(m.Name), "sidecar-injector") &&
			!strings.Contains(strings.ToLower(m.Name), "istio") &&
			!strings.Contains(strings.ToLower(m.Name), "linkerd") {
			continue
		}
		for _, w := range m.Webhooks {
			fp := "Fail"
			if w.FailurePolicy != nil {
				fp = string(*w.FailurePolicy)
			}
			if fp == "Ignore" {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevMedium,
					Title:          fmt.Sprintf("Mesh sidecar injector %q is fail-open", m.Name),
					Description:    "If the injector pod is unreachable, pods are admitted *without* the sidecar. An attacker who can DoS the injector achieves mesh bypass for new pods.",
					Resource:       scanner.Resource{Kind: "MutatingWebhookConfiguration", Name: m.Name},
					Evidence:       fmt.Sprintf("webhook=%s failurePolicy=%s", w.Name, fp),
					Impact:         "Mesh bypass for newly-created pods after a control-plane outage or attacker-induced DoS.",
					Recommendation: "Run multiple injector replicas + PDB and set failurePolicy=Fail.",
					Tags:           []string{"service-mesh", "injector", "fail-open"},
				})
			}
		}
	}
	return out
}

func ruleMeshEgressOpen(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	mesh, _ := detectMesh(inv)
	if mesh != meshIstio {
		return nil
	}

	hasEgressGw := false
	for _, p := range inv.Pods {
		if strings.Contains(strings.ToLower(p.Name), "istio-egressgateway") {
			hasEgressGw = true
			break
		}
	}
	if hasEgressGw {
		return nil
	}
	for _, s := range inv.Services {
		if strings.Contains(strings.ToLower(s.Name), "egressgateway") {
			hasEgressGw = true
			break
		}
	}
	if hasEgressGw {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevMedium,
		Title:          "Istio installed but no istio-egressgateway present",
		Description:    "Without an egress gateway, sidecars send external traffic directly. There is no choke point to enforce TLS-pinning, monitor egress destinations, or block phone-home traffic from compromised pods.",
		Resource:       scanner.Resource{Kind: "Cluster"},
		Evidence:       "no Pod / Service named *istio-egressgateway* found in inventory",
		Impact:         "Compromised workloads have direct path to external C2; egress detection relies entirely on NetworkPolicy.",
		Recommendation: "Deploy `istio-egressgateway` and use Sidecar / VirtualService configs to force outbound traffic through it.",
		Tags:           []string{"service-mesh", "istio", "egress-gateway"},
	}}
}
