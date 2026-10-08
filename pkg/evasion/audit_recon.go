package evasion

import (
	"context"
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func AuditRecon(ctx context.Context, sess *kubectx.Session, inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding

	cms, err := sess.Client.CoreV1().ConfigMaps("kube-system").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range cms.Items {
			name := strings.ToLower(cm.Name)
			if !strings.Contains(name, "audit") {
				continue
			}
			out = append(out, scanner.Finding{
				RuleID:         "KH-EVA-002",
				Category:       scanner.CatEvasion,
				Severity:       scanner.SevInfo,
				Title:          fmt.Sprintf("Audit configuration candidate: kube-system/%s", cm.Name),
				Description:    "A ConfigMap in kube-system has 'audit' in its name and is probably the audit-policy source for the API server. An attacker with PATCH on this ConfigMap could lower audit verbosity on the NEXT API-server restart. This scanner does NOT modify it.",
				Resource:       scanner.Resource{Kind: "ConfigMap", Namespace: "kube-system", Name: cm.Name},
				Evidence:       fmt.Sprintf("keys=%s", strings.Join(configMapKeys(cm.Data), ",")),
				Recommendation: "Audit who has patch rights on this ConfigMap (`kubectl auth can-i patch cm/" + cm.Name + " -n kube-system --as=SUBJECT`). Restrict it to cluster operators only.",
				Tags:           []string{"evasion", "audit-recon"},
			})
		}
	}

	apiPods, err := sess.Client.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err == nil {
		for _, p := range apiPods.Items {
			flags := collectFlags(p.Spec.Containers)
			if hasAuditFlags(flags) {
				out = append(out, scanner.Finding{
					RuleID:         "KH-EVA-003",
					Category:       scanner.CatEvasion,
					Severity:       scanner.SevInfo,
					Title:          fmt.Sprintf("API-server audit pipeline visible on pod %s/%s", p.Namespace, p.Name),
					Description:    "The kube-apiserver pod is running with explicit --audit-policy-file / --audit-webhook-config-file flags. This tells us where audit records are being sent. This finding is informational and helps plan red-team engagement windows with the SOC.",
					Resource:       scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
					Evidence:       truncate(strings.Join(flags, " "), 400),
					Recommendation: "Confirm with the SOC which pipeline consumes these events and plan the engagement window accordingly.",
					Tags:           []string{"evasion", "audit-recon"},
				})
			}
		}
	}

	return out
}

func configMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func collectFlags(cs []corev1.Container) []string {
	out := make([]string, 0, 8)
	for _, c := range cs {
		out = append(out, c.Command...)
		out = append(out, c.Args...)
	}
	return out
}

func hasAuditFlags(flags []string) bool {
	joined := strings.Join(flags, " ")
	return strings.Contains(joined, "--audit-policy-file") ||
		strings.Contains(joined, "--audit-webhook-config-file")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
