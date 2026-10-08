package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func ExposedDashboardRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-EXPOSED-ARGOCD", Title: "Argo CD UI Service detected", Category: scanner.CatNetwork, Fn: ruleExposedArgoCD},
		{ID: "KH-EXPOSED-RANCHER", Title: "Rancher / RKE management UI Service detected", Category: scanner.CatNetwork, Fn: ruleExposedRancher},
		{ID: "KH-EXPOSED-PROMETHEUS", Title: "Prometheus Service detected (default has no auth)", Category: scanner.CatNetwork, Fn: ruleExposedPrometheus},
		{ID: "KH-EXPOSED-GRAFANA", Title: "Grafana Service detected (default admin/admin)", Category: scanner.CatNetwork, Fn: ruleExposedGrafana},
		{ID: "KH-EXPOSED-KIALI", Title: "Kiali (Istio) UI Service detected", Category: scanner.CatNetwork, Fn: ruleExposedKiali},
		{ID: "KH-EXPOSED-JAEGER", Title: "Jaeger UI Service detected", Category: scanner.CatNetwork, Fn: ruleExposedJaeger},
		{ID: "KH-EXPOSED-SPINNAKER", Title: "Spinnaker UI Service detected", Category: scanner.CatNetwork, Fn: ruleExposedSpinnaker},
		{ID: "KH-EXPOSED-CHARTMUSEUM", Title: "Helm ChartMuseum Service detected", Category: scanner.CatNetwork, Fn: ruleExposedChartMuseum},
		{ID: "KH-EXPOSED-KUBEAPPS", Title: "Kubeapps UI Service detected", Category: scanner.CatNetwork, Fn: ruleExposedKubeapps},
		{ID: "KH-EXPOSED-VAULT-UI", Title: "HashiCorp Vault UI Service detected", Category: scanner.CatNetwork, Fn: ruleExposedVault},
	}
}

type dashboardSig struct {
	id          string
	displayName string
	matchSvc    []string
	matchImage  []string
	defaultPort []int32
	severity    scanner.Severity
	impact      string
	recommend   string
	tags        []string
}

func emitExposed(inv *scanner.Inventory, sig dashboardSig) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Services {
		nameMatch := false
		for _, sub := range sig.matchSvc {
			if strings.Contains(strings.ToLower(s.Name), sub) {
				nameMatch = true
				break
			}
		}

		imgMatch := false
		if !nameMatch && len(sig.matchImage) > 0 {
			for _, p := range inv.Pods {
				if p.Namespace != s.Namespace {
					continue
				}
				if !podMatchesService(p.Labels, s.Spec.Selector) {
					continue
				}
				for _, c := range p.Spec.Containers {
					for _, sub := range sig.matchImage {
						if strings.Contains(strings.ToLower(c.Image), sub) {
							imgMatch = true
						}
					}
				}
			}
		}
		if !nameMatch && !imgMatch {
			continue
		}
		exposed := false
		exposureKind := "ClusterIP"
		switch s.Spec.Type {
		case "LoadBalancer":
			exposed = true
			exposureKind = "LoadBalancer"
		case "NodePort":
			exposed = true
			exposureKind = "NodePort"
		}
		if len(s.Spec.ExternalIPs) > 0 {
			exposed = true
			exposureKind += "+externalIPs"
		}

		sev := sig.severity
		if !exposed {
			sev = downgradeSeverity(sev, 1)
		}
		ports := []string{}
		for _, p := range s.Spec.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
		}
		out = append(out, scanner.Finding{
			RuleID:         sig.id,
			Category:       scanner.CatNetwork,
			Severity:       sev,
			Title:          fmt.Sprintf("%s detected at Service %s/%s (type=%s)", sig.displayName, s.Namespace, s.Name, exposureKind),
			Description:    fmt.Sprintf("%s frequently ships with weak / no authentication on the default install. Reachable instances are a high-value pentest target.", sig.displayName),
			Resource:       scanner.Resource{Kind: "Service", Namespace: s.Namespace, Name: s.Name},
			Evidence:       fmt.Sprintf("service.type=%s ports=%v exposed=%v", s.Spec.Type, ports, exposed),
			Impact:         sig.impact,
			Recommendation: sig.recommend,
			Tags:           append(append([]string{}, sig.tags...), "exposed-dashboard"),
		})
	}
	return out
}

func podMatchesService(podLabels, sel map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, v := range sel {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

func downgradeSeverity(s scanner.Severity, steps int) scanner.Severity {
	order := []scanner.Severity{scanner.SevCritical, scanner.SevHigh, scanner.SevMedium, scanner.SevLow, scanner.SevInfo}
	for i, x := range order {
		if x == s {
			ni := i + steps
			if ni >= len(order) {
				return scanner.SevInfo
			}
			return order[ni]
		}
	}
	return s
}

func ruleExposedArgoCD(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-ARGOCD",
		displayName: "Argo CD",
		matchSvc:    []string{"argocd-server", "argo-cd-server"},
		matchImage:  []string{"argoproj/argocd"},
		severity:    scanner.SevHigh,
		impact:      "Argo CD with default `admin` password, anonymous read, or `users.anonymous.enabled=true` exposes every git-tracked manifest + grants cluster-admin (Argo's own SA is usually cluster-admin).",
		recommend:   "Disable anonymous access (`users.anonymous.enabled: false`), rotate the initial admin password (`argocd-initial-admin-secret`), enforce SSO, and place the UI behind an authenticating ingress.",
		tags:        []string{"argocd", "gitops"},
	})
}

func ruleExposedRancher(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-RANCHER",
		displayName: "Rancher / RKE management",
		matchSvc:    []string{"rancher"},
		matchImage:  []string{"rancher/rancher"},
		severity:    scanner.SevHigh,
		impact:      "Rancher manages multiple downstream clusters. A single pentester foothold here yields admin to every managed cluster.",
		recommend:   "Strict auth providers (LDAP/SAML/OIDC), 2FA where possible, restrict public exposure.",
		tags:        []string{"rancher"},
	})
}

func ruleExposedPrometheus(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-PROMETHEUS",
		displayName: "Prometheus",
		matchSvc:    []string{"prometheus", "prom-server"},
		matchImage:  []string{"prom/prometheus", "prometheus/prometheus"},
		severity:    scanner.SevMedium,
		impact:      "Prometheus default install has no authentication. The `/metrics`, `/api/v1/query`, and `/-/reload` endpoints leak workload metrics, internal IPs, and admin URLs. Some instances also expose `/-/admin` shutdown endpoints.",
		recommend:   "Front Prometheus with an auth proxy (oauth2-proxy, nginx-basic-auth, kube-rbac-proxy). Disable `--web.enable-admin-api` unless required.",
		tags:        []string{"prometheus", "metrics"},
	})
}

func ruleExposedGrafana(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-GRAFANA",
		displayName: "Grafana",
		matchSvc:    []string{"grafana"},
		matchImage:  []string{"grafana/grafana"},
		severity:    scanner.SevMedium,
		impact:      "Default install ships with admin/admin. Authenticated users can run Prometheus/InfluxDB query against backend datasources, including those connected to internal services.",
		recommend:   "Rotate admin password; configure SSO / LDAP; disable anonymous access in `grafana.ini`.",
		tags:        []string{"grafana"},
	})
}

func ruleExposedKiali(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-KIALI",
		displayName: "Kiali (Istio observability)",
		matchSvc:    []string{"kiali"},
		matchImage:  []string{"quay.io/kiali"},
		severity:    scanner.SevMedium,
		impact:      "Kiali maps the service mesh topology and identities. With anonymous access enabled, the entire service graph + identity boundaries are visible — a recon goldmine before lateral movement.",
		recommend:   "Set `auth.strategy: openshift|token|header` in the Kiali CR; never use `anonymous`.",
		tags:        []string{"kiali", "istio"},
	})
}

func ruleExposedJaeger(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-JAEGER",
		displayName: "Jaeger UI",
		matchSvc:    []string{"jaeger-query", "jaeger-ui"},
		matchImage:  []string{"jaegertracing/"},
		severity:    scanner.SevLow,
		impact:      "Trace data leaks request paths, query parameters, and frequently authentication tokens that ended up in URL fragments.",
		recommend:   "Front with auth proxy or restrict to internal CIDRs.",
		tags:        []string{"jaeger", "tracing"},
	})
}

func ruleExposedSpinnaker(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-SPINNAKER",
		displayName: "Spinnaker",
		matchSvc:    []string{"spin-deck", "spinnaker"},
		matchImage:  []string{"spinnaker/", "armory/"},
		severity:    scanner.SevHigh,
		impact:      "Spinnaker's pipelines deploy to dozens of accounts — compromise = supply-chain attack on every pipeline target.",
		recommend:   "Mandatory SSO, X.509 mTLS for the Halyard config, restrict the deck UI to corp network.",
		tags:        []string{"spinnaker"},
	})
}

func ruleExposedChartMuseum(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-CHARTMUSEUM",
		displayName: "Helm ChartMuseum",
		matchSvc:    []string{"chartmuseum"},
		matchImage:  []string{"chartmuseum/"},
		severity:    scanner.SevMedium,
		impact:      "Default ChartMuseum allows anonymous chart upload — an attacker can publish a backdoored chart that the cluster (or any consumer) installs next.",
		recommend:   "Set `BASIC_AUTH_USER` / `BASIC_AUTH_PASS`; allow uploads only from CI; protect with NetworkPolicy.",
		tags:        []string{"chartmuseum", "supply-chain"},
	})
}

func ruleExposedKubeapps(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-KUBEAPPS",
		displayName: "Kubeapps",
		matchSvc:    []string{"kubeapps"},
		matchImage:  []string{"bitnami/kubeapps", "kubeapps/"},
		severity:    scanner.SevHigh,
		impact:      "Kubeapps installs Helm charts using the caller's RBAC; mis-RBAC'd cluster-admin tokens have led to several real-world breaches.",
		recommend:   "Strict OIDC; restrict the app-installation cluster role; never expose the UI publicly.",
		tags:        []string{"kubeapps", "supply-chain"},
	})
}

func ruleExposedVault(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return emitExposed(inv, dashboardSig{
		id:          "KH-EXPOSED-VAULT-UI",
		displayName: "HashiCorp Vault",
		matchSvc:    []string{"vault"},
		matchImage:  []string{"hashicorp/vault", "vault:"},
		severity:    scanner.SevHigh,
		impact:      "Vault holds the cluster's secrets. Even if the UI requires login, the unauthenticated `/v1/sys/health` and `/v1/sys/seal-status` endpoints expose unsealing state — useful for timed unsealing-key replay attacks.",
		recommend:   "Disable the UI in production (`ui = false`); restrict the API to known caller pods via NetworkPolicy.",
		tags:        []string{"vault", "secrets"},
	})
}
