package rules

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
)

func SATokenRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-CRED-SA-LEGACY", Title: "Legacy long-lived ServiceAccount token (no exp)", Category: scanner.CatSecret, Fn: ruleSALegacyToken},
		{ID: "KH-CRED-SA-PROJECTED-LIFETIME", Title: "Projected token expirationSeconds excessive", Category: scanner.CatSecret, Fn: ruleSAProjectedLifetime},
		{ID: "KH-CRED-SA-AUDIENCE-WILDCARD", Title: "Projected token has no `audiences` binding", Category: scanner.CatSecret, Fn: ruleSAAudienceWildcard},
		{ID: "KH-CRED-SA-AUTOMOUNT", Title: "Pod auto-mounts API token but does not declare API access", Category: scanner.CatSecret, Fn: ruleSAAutomountUnused},
		{ID: "KH-CRED-SA-DEFAULT-USED", Title: "Pod runs as `default` ServiceAccount", Category: scanner.CatSecret, Fn: ruleSADefaultUsed},
		{ID: "KH-CRED-SA-PULLSECRET-EXFIL", Title: "ServiceAccount references imagePullSecret with leakable creds", Category: scanner.CatSecret, Fn: ruleSAPullSecret},
	}
}

type jwtClaims struct {
	Iss string                 `json:"iss"`
	Sub string                 `json:"sub"`
	Aud []string               `json:"aud"`
	Exp int64                  `json:"exp"`
	Iat int64                  `json:"iat"`
	Nbf int64                  `json:"nbf"`
	K8s map[string]interface{} `json:"kubernetes.io"`
}

func decodeJWT(s string) (jwtClaims, bool) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return jwtClaims{}, false
	}
	pad := func(p string) string {
		if m := len(p) % 4; m != 0 {
			return p + strings.Repeat("=", 4-m)
		}
		return p
	}
	payload, err := base64.URLEncoding.DecodeString(pad(parts[1]))
	if err != nil {
		payload, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return jwtClaims{}, false
		}
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return jwtClaims{}, false
	}
	c := jwtClaims{}
	if v, ok := raw["iss"].(string); ok {
		c.Iss = v
	}
	if v, ok := raw["sub"].(string); ok {
		c.Sub = v
	}
	if v, ok := raw["aud"].(string); ok {
		c.Aud = []string{v}
	} else if vs, ok := raw["aud"].([]interface{}); ok {
		for _, x := range vs {
			if s, ok := x.(string); ok {
				c.Aud = append(c.Aud, s)
			}
		}
	}
	if v, ok := raw["exp"].(float64); ok {
		c.Exp = int64(v)
	}
	if v, ok := raw["iat"].(float64); ok {
		c.Iat = int64(v)
	}
	if v, ok := raw["kubernetes.io"].(map[string]interface{}); ok {
		c.K8s = v
	}
	return c, true
}

func ruleSALegacyToken(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Secrets {
		if s.Type != corev1.SecretTypeServiceAccountToken {
			continue
		}
		jwt, ok := decodeJWT(string(s.Data["token"]))
		evidence := fmt.Sprintf("type=%s", s.Type)
		neverExpires := false
		if ok {
			evidence += fmt.Sprintf(" iss=%s sub=%s exp=%d", jwt.Iss, jwt.Sub, jwt.Exp)
			if jwt.Exp == 0 {
				neverExpires = true
			}
		} else {
			neverExpires = true
		}
		sev := scanner.SevHigh
		impact := "Legacy SA token Secrets have no expiry. If the token leaks (logs, backups, image layers, audit dumps) the attacker has indefinite cluster access bound to that SA's RBAC."
		if !neverExpires {

			sev = scanner.SevMedium
			impact = "Although the kube-apiserver may now refresh tokens, the underlying Secret still serves as a long-lived fallback credential."
		}
		out = append(out, scanner.Finding{
			Severity:       sev,
			Title:          fmt.Sprintf("Legacy ServiceAccount-token Secret in %s/%s", s.Namespace, s.Name),
			Description:    "Found a `kubernetes.io/service-account-token` Secret. Since 1.24 these are not auto-created; their continued existence is usually accidental and a credential-theft target.",
			Resource:       scanner.Resource{Kind: "Secret", Namespace: s.Namespace, Name: s.Name},
			Evidence:       evidence,
			Impact:         impact,
			Recommendation: "Delete the Secret and switch consumers to projected service-account tokens (TokenRequest API). `kubectl delete secret " + s.Name + " -n " + s.Namespace + "`",
			RemediationCmd: fmt.Sprintf("kubectl delete secret %s -n %s", s.Name, s.Namespace),
			Tags:           []string{"sa-token", "credential", "legacy"},
		})
	}
	return out
}

func ruleSAProjectedLifetime(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.Projected == nil {
				continue
			}
			for _, src := range v.Projected.Sources {
				if src.ServiceAccountToken == nil {
					continue
				}
				exp := int64(0)
				if src.ServiceAccountToken.ExpirationSeconds != nil {
					exp = *src.ServiceAccountToken.ExpirationSeconds
				}
				if exp >= 600 && exp <= 3600 {
					continue
				}
				sev := scanner.SevMedium
				if exp == 0 || exp > 24*3600 {
					sev = scanner.SevHigh
				}
				out = append(out, scanner.Finding{
					Severity:       sev,
					Title:          fmt.Sprintf("Projected SA token with %ds lifetime on %s/%s", exp, p.Namespace, p.Name),
					Description:    fmt.Sprintf("Volume %q projects a service-account token but the lifetime is unusually long (or unset → defaults to 1h or longer depending on kubelet).", v.Name),
					Resource:       podResource(p),
					Evidence:       fmt.Sprintf("volume=%s expirationSeconds=%d audiences=%v", v.Name, exp, src.ServiceAccountToken.Audience),
					Impact:         "Long-lived projected tokens reduce the benefit of the TokenRequest mechanism. A leaked token remains valid until expiry.",
					Recommendation: "Set expirationSeconds to ≤3600 (1h). The kubelet will rotate the token automatically.",
					Tags:           []string{"sa-token", "projected", "lifetime"},
				})
			}
		}
	}
	return out
}

func ruleSAAudienceWildcard(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.Projected == nil {
				continue
			}
			for _, src := range v.Projected.Sources {
				if src.ServiceAccountToken == nil {
					continue
				}
				audience := src.ServiceAccountToken.Audience
				if audience == "" || audience == "https://kubernetes.default.svc" || audience == "kubernetes.default.svc" {
					out = append(out, scanner.Finding{
						Severity:       scanner.SevMedium,
						Title:          fmt.Sprintf("Projected SA token has no audience binding on %s/%s", p.Namespace, p.Name),
						Description:    fmt.Sprintf("Volume %q does not specify a non-default `audience`. The token can be replayed against any service that accepts the default API-server audience.", v.Name),
						Resource:       podResource(p),
						Evidence:       fmt.Sprintf("volume=%s audience=%q", v.Name, audience),
						Impact:         "Without a service-specific audience the token is acceptable to any consumer that trusts the cluster issuer.",
						Recommendation: "Set `audience` to a workload-specific value (e.g. `vault`, `istio-ca`) so the token is bound to that audience only.",
						Tags:           []string{"sa-token", "projected", "audience"},
					})
				}
			}
		}
	}
	return out
}

func ruleSAAutomountUnused(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	saUsage := map[string]bool{}

	for _, sa := range inv.ServiceAccounts {
		saUsage[sa.Namespace+"/"+sa.Name] = false
	}
	for _, rb := range inv.RoleBindings {
		for _, s := range rb.Subjects {
			if s.Kind == "ServiceAccount" {
				saUsage[rb.Namespace+"/"+s.Name] = true
			}
		}
	}
	for _, crb := range inv.ClusterRoleBindings {
		for _, s := range crb.Subjects {
			if s.Kind == "ServiceAccount" && s.Namespace != "" {
				saUsage[s.Namespace+"/"+s.Name] = true
			}
		}
	}
	for _, p := range inv.Pods {
		if !scanner.AutomountToken(inv, &p) {
			continue
		}
		saName := p.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		key := p.Namespace + "/" + saName
		if saUsage[key] {
			continue
		}

		if strings.HasPrefix(p.Namespace, "kube-") || p.Namespace == "default" {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("Pod auto-mounts API token but SA %q has no RBAC bindings on %s/%s", saName, p.Namespace, p.Name),
			Description:    "The pod gets a kube API token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token but the SA has no RoleBindings. If a workload doesn't need to talk to the API, mounting the token only adds a credential that an attacker who lands inside the container can use to enumerate the cluster (calling /api/v1/namespaces, etc.).",
			Resource:       podResource(p),
			Evidence:       fmt.Sprintf("sa=%s/%s automountServiceAccountToken=true bindings=0", p.Namespace, saName),
			Impact:         "An attacker inside the container can `cat /var/run/secrets/kubernetes.io/serviceaccount/token` and use it as a Bearer; even a no-RBAC SA can usually GET /api/v1, /version, /openapi/v2 → information disclosure.",
			Recommendation: "Set `automountServiceAccountToken: false` on the pod spec (or the SA) when the workload doesn't talk to the kube API.",
			Tags:           []string{"sa-token", "automount"},
		})
	}
	return out
}

func ruleSADefaultUsed(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		sa := p.Spec.ServiceAccountName
		if sa != "" && sa != "default" {
			continue
		}

		if !scanner.AutomountToken(inv, &p) {
			continue
		}
		if strings.HasPrefix(p.Namespace, "kube-") {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevLow,
			Title:          fmt.Sprintf("Pod %s/%s runs as the `default` ServiceAccount", p.Namespace, p.Name),
			Description:    "Pods that don't set spec.serviceAccountName fall back to `default`. That account is shared by every workload in the namespace which makes auditing impossible and concentrates blast radius.",
			Resource:       podResource(p),
			Evidence:       fmt.Sprintf("sa=default ns=%s", p.Namespace),
			Impact:         "If the `default` SA accidentally gets a binding (very common in onboarding), every pod in the namespace inherits the privilege.",
			Recommendation: "Create a dedicated SA per workload and set spec.serviceAccountName.",
			Tags:           []string{"sa-token", "default"},
		})
	}
	return out
}

func ruleSAPullSecret(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {

	secretByKey := map[string]*corev1.Secret{}
	for i := range inv.Secrets {
		s := &inv.Secrets[i]
		secretByKey[s.Namespace+"/"+s.Name] = s
	}
	var out []scanner.Finding
	for _, sa := range inv.ServiceAccounts {
		for _, ref := range sa.ImagePullSecrets {
			s, ok := secretByKey[sa.Namespace+"/"+ref.Name]
			if !ok || s.Type != corev1.SecretTypeDockerConfigJson {
				continue
			}
			cfg, ok := s.Data[".dockerconfigjson"]
			if !ok {
				continue
			}
			var parsed struct {
				Auths map[string]struct {
					Auth     string `json:"auth"`
					Username string `json:"username"`
					Password string `json:"password"`
				} `json:"auths"`
			}
			if err := json.Unmarshal(cfg, &parsed); err != nil {
				continue
			}
			for registry := range parsed.Auths {
				var exposedPods []string
				for _, pod := range inv.Pods {
					if pod.Namespace != sa.Namespace {
						continue
					}
					for _, container := range allContainers(pod) {
						exposed := false
						for _, env := range container.EnvFrom {
							exposed = exposed || (env.SecretRef != nil && env.SecretRef.Name == ref.Name)
						}
						for _, env := range container.Env {
							exposed = exposed || (env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil && env.ValueFrom.SecretKeyRef.Name == ref.Name)
						}
						for _, mount := range container.VolumeMounts {
							for _, volume := range pod.Spec.Volumes {
								if volume.Name != mount.Name {
									continue
								}
								exposed = exposed || (volume.Secret != nil && volume.Secret.SecretName == ref.Name)
								if volume.Projected != nil {
									for _, source := range volume.Projected.Sources {
										exposed = exposed || (source.Secret != nil && source.Secret.Name == ref.Name)
									}
								}
							}
						}
						if exposed {
							exposedPods = append(exposedPods, pod.Name+"/"+container.Name)
						}
					}
				}
				if len(exposedPods) == 0 {
					continue
				}
				out = append(out, scanner.Finding{
					Severity:       scanner.SevHigh,
					Title:          fmt.Sprintf("Registry credentials for %s are explicitly exposed to workloads", registry),
					Description:    "An image-pull credential is also explicitly mounted or injected into a container environment. A compromise of that container can expose registry credentials. An imagePullSecrets reference alone does not mount credentials into a pod.",
					Resource:       scanner.Resource{Kind: "ServiceAccount", Namespace: sa.Namespace, Name: sa.Name},
					Evidence:       fmt.Sprintf("registry=%s pullSecret=%s/%s exposedContainers=%v", registry, sa.Namespace, ref.Name, exposedPods),
					Impact:         "An attacker controlling an exposed container may steal registry credentials. Registry write authority is not established by the secret's existence.",
					Recommendation: "Use a dedicated read-only registry account, scope it to a single repo, and rotate. For higher-trust environments use IAM-based pull (IRSA, Workload Identity) and remove the static credential entirely.",
					Tags:           []string{"sa-token", "pullsecret", "supply-chain"},
				})
			}
		}
	}
	return out
}

var _ = time.Now
