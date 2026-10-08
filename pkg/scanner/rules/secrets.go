package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
)

func SecretRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-SEC-001", Title: "Sensitive data in ConfigMap", Category: scanner.CatSecret, Fn: ruleSEC001ConfigMapSecret},
		{ID: "KH-SEC-002", Title: "Long-lived ServiceAccount token Secret", Category: scanner.CatSecret, Fn: ruleSEC002SAToken},
		{ID: "KH-SEC-003", Title: "Secret-via-env from entire Secret (envFrom)", Category: scanner.CatSecret, Fn: ruleSEC003EnvFrom},
		{ID: "KH-SEC-004", Title: "Helm release secret exposed", Category: scanner.CatSecret, Fn: ruleSEC004Helm},
	}
}

var secretHinters = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|secret|token|apikey|api_key|access_key|private_key|bearer|client_secret)`),
	regexp.MustCompile(`-----BEGIN .* PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)aws_access_key_id|aws_secret_access_key`),
	regexp.MustCompile(`(?i)slack.*(xoxb|xoxp|xoxa)-`),
	regexp.MustCompile(`(?i)ghp_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`(?i)eyJ[A-Za-z0-9_\-]{20,}\.`),
}

func ruleSEC001ConfigMapSecret(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, cm := range inv.ConfigMaps {
		for key, val := range cm.Data {
			if len(val) > 4096 {
				val = val[:4096]
			}
			var matched string
			for _, rx := range secretHinters {
				if rx.MatchString(key) || rx.MatchString(val) {
					matched = rx.String()
					break
				}
			}
			if matched == "" {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          "Potential secret stored in ConfigMap",
				Description:    fmt.Sprintf("ConfigMap %s/%s key %q matches sensitive pattern.", cm.Namespace, cm.Name, key),
				Resource:       scanner.Resource{Kind: "ConfigMap", Namespace: cm.Namespace, Name: cm.Name},
				Evidence:       fmt.Sprintf("key=%s pattern=%s", key, matched),
				Impact:         "ConfigMaps are world-readable to anyone with `get configmaps`. Any credential here is effectively public inside the namespace.",
				Recommendation: "Move sensitive data to a Secret (ideally encrypted at rest / external vault). Update workloads to mount Secret instead.",
				Tags:           []string{"secret", "exposure"},
			})
		}
	}
	return out
}

func ruleSEC002SAToken(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Secrets {
		if s.Type != corev1.SecretTypeServiceAccountToken {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          "Long-lived ServiceAccount token Secret",
			Description:    fmt.Sprintf("Secret %s/%s is a legacy SA token (kubernetes.io/service-account-token).", s.Namespace, s.Name),
			Resource:       scanner.Resource{Kind: "Secret", Namespace: s.Namespace, Name: s.Name},
			Evidence:       "type=kubernetes.io/service-account-token",
			Impact:         "Legacy SA tokens have no expiry. If leaked they remain valid forever unless the SA is deleted.",
			Recommendation: "Since K8s 1.24 use TokenRequest-based projected tokens (expire+audience). Delete legacy Secret-based tokens where not strictly required.",
			RemediationCmd: fmt.Sprintf("kubectl delete secret %s -n %s", s.Name, s.Namespace),
			Tags:           []string{"secret", "sa-token", "legacy"},
		})
	}
	return out
}

func ruleSEC003EnvFrom(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			for _, src := range c.EnvFrom {
				if src.SecretRef == nil {
					continue
				}
				out = append(out, scanner.Finding{
					Severity:       scanner.SevLow,
					Title:          "Entire Secret bulk-mounted via envFrom",
					Description:    fmt.Sprintf("Container %q in pod %s/%s uses envFrom.secretRef=%s, mounting every key as env var.", c.Name, p.Namespace, p.Name, src.SecretRef.Name),
					Resource:       podResource(p),
					Recommendation: "Reference only the specific Secret keys actually needed via env.valueFrom.secretKeyRef.",
					Tags:           []string{"secret", "hygiene"},
				})
			}
		}
	}
	return out
}

func ruleSEC004Helm(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Secrets {
		if !strings.HasPrefix(s.Name, "sh.helm.release.") {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevInfo,
			Title:          "Helm release state Secret present",
			Description:    fmt.Sprintf("Secret %s/%s stores Helm release state; its release-values portion may include chart-provided credentials.", s.Namespace, s.Name),
			Resource:       scanner.Resource{Kind: "Secret", Namespace: s.Namespace, Name: s.Name},
			Recommendation: "Ensure sensitive values are passed via --set-file / external secret manager and not embedded in values.yaml.",
			Tags:           []string{"secret", "helm"},
		})
	}
	return out
}
