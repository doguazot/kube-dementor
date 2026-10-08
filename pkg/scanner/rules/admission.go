package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	admissionv1 "k8s.io/api/admissionregistration/v1"
)

func AdmissionRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-ADM-001", Title: "Admission webhook fails open (failurePolicy=Ignore)",
			Category: scanner.CatAdmission, Fn: admWebhookFailOpen},
		{ID: "KH-ADM-002", Title: "Admission webhook missing caBundle / TLS misconfig",
			Category: scanner.CatAdmission, Fn: admWebhookNoCA},
		{ID: "KH-ADM-003", Title: "Mutating webhook with wildcard scope + CREATE rights (persistence vector)",
			Category: scanner.CatAdmission, Fn: admWildcardMutating},
		{ID: "KH-ADM-004", Title: "Policy engine present but no enforce-mode rules found",
			Category: scanner.CatAdmission, Fn: admEmptyPolicyEngine},
	}
}

func admWebhookFailOpen(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	check := func(name, kind string, fp *admissionv1.FailurePolicyType, sideEffect string) {
		if fp != nil && *fp == admissionv1.Ignore {
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          fmt.Sprintf("%s %q has failurePolicy=Ignore", kind, name),
				Description:    "If the webhook backend is unreachable (crashed, network-partitioned), the API server accepts the request anyway. An attacker who can DoS the backend can push pods/resources that would otherwise be rejected.",
				Resource:       scanner.Resource{Kind: kind, Name: name},
				Evidence:       "failurePolicy=Ignore, sideEffects=" + sideEffect,
				Impact:         "Policy bypass by crashing or slowing the webhook backend.",
				Recommendation: "Set failurePolicy=Fail on security-critical webhooks, or deploy the backend with a PDB and multiple replicas so it cannot be taken down easily.",
				References: []string{
					"https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/",
				},
			})
		}
	}
	for _, m := range inv.MutatingWebhooks {
		for _, w := range m.Webhooks {
			se := ""
			if w.SideEffects != nil {
				se = string(*w.SideEffects)
			}
			check(w.Name, "MutatingWebhookConfiguration", w.FailurePolicy, se)
		}
	}
	for _, v := range inv.ValidatingWebhooks {
		for _, w := range v.Webhooks {
			se := ""
			if w.SideEffects != nil {
				se = string(*w.SideEffects)
			}
			check(w.Name, "ValidatingWebhookConfiguration", w.FailurePolicy, se)
		}
	}
	return out
}

func admWebhookNoCA(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	check := func(name, kind string, cfg admissionv1.WebhookClientConfig) {
		if len(cfg.CABundle) == 0 {
			out = append(out, scanner.Finding{
				Severity:       scanner.SevMedium,
				Title:          fmt.Sprintf("%s %q has empty caBundle", kind, name),
				Description:    "The API server cannot verify the TLS identity of the webhook backend. An on-cluster attacker (or BGP/ARP spoof) may intercept admission traffic, silently approve malicious pods, or leak the full admission payload (including secrets).",
				Resource:       scanner.Resource{Kind: kind, Name: name},
				Evidence:       "webhooks[].clientConfig.caBundle is empty",
				Impact:         "MITM of admission decisions, data exfil from admission payloads.",
				Recommendation: "Ship the webhook backend with its own PKI and set caBundle to the signing CA; for cert-manager users, use ca-injector annotations.",
			})
		}
	}
	for _, m := range inv.MutatingWebhooks {
		for _, w := range m.Webhooks {
			check(w.Name, "MutatingWebhookConfiguration", w.ClientConfig)
		}
	}
	for _, v := range inv.ValidatingWebhooks {
		for _, w := range v.Webhooks {
			check(w.Name, "ValidatingWebhookConfiguration", w.ClientConfig)
		}
	}
	return out
}

func admWildcardMutating(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, m := range inv.MutatingWebhooks {

		if isKnownSystemController(m.Name) {
			continue
		}
		for _, w := range m.Webhooks {
			wildcardAll := false
			hasCreate := false
			for _, r := range w.Rules {
				for _, o := range r.Operations {
					if o == admissionv1.Create || o == "*" {
						hasCreate = true
					}
				}
				for _, g := range r.Rule.APIGroups {
					if g == "*" {
						for _, rr := range r.Rule.Resources {
							if rr == "*" {
								wildcardAll = true
							}
						}
					}
				}
			}
			if wildcardAll && hasCreate {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevHigh,
					Title:          fmt.Sprintf("Mutating webhook %q rewrites every new resource (scope=*)", w.Name),
					Description:    "A mutating webhook configured with apiGroups=['*'], resources=['*'], operations including CREATE can silently inject sidecars, environment variables or service-account tokens into every new object cluster-wide. This is a textbook persistence mechanism.",
					Resource:       scanner.Resource{Kind: "MutatingWebhookConfiguration", Name: m.Name},
					Evidence:       "apiGroups=*, resources=*, operations include CREATE",
					Impact:         "Cluster-wide persistence + data exfiltration via implanted sidecars or init-containers.",
					Recommendation: "Scope the webhook rules to the exact resources it needs (e.g. pods only). Audit who can PATCH this MutatingWebhookConfiguration.",
				})
			}
		}
	}
	return out
}

func admEmptyPolicyEngine(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	gatekeeperSeen := false
	kyvernoSeen := false
	for _, ns := range inv.Namespaces {
		name := strings.ToLower(ns.Name)
		if strings.Contains(name, "gatekeeper") {
			gatekeeperSeen = true
		}
		if strings.Contains(name, "kyverno") {
			kyvernoSeen = true
		}
	}

	for _, p := range inv.Pods {
		img := strings.ToLower(p.Spec.Containers[0].Image)
		if strings.Contains(img, "gatekeeper") {
			gatekeeperSeen = true
		}
		if strings.Contains(img, "kyverno") {
			kyvernoSeen = true
		}
	}
	var out []scanner.Finding
	if gatekeeperSeen {
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          "OPA Gatekeeper installed — verify enforce-mode constraints are in place",
			Description:    "Kube-Dementor cannot enumerate Gatekeeper Constraints through the generic Kubernetes API (they're CRD-based). Confirm manually that ConstraintTemplates exist AND Constraints are installed with enforcementAction=deny.",
			Resource:       scanner.Resource{Kind: "Cluster", Name: "gatekeeper"},
			Recommendation: "kubectl get constraints --all-namespaces -o json | jq '.items[] | {name:.metadata.name, enforcementAction:.spec.enforcementAction}'",
			References:     []string{"https://open-policy-agent.github.io/gatekeeper/website/docs/howto"},
		})
	}
	if kyvernoSeen {
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          "Kyverno installed — verify enforce-mode policies are in place",
			Description:    "Kyverno policies default to `audit` mode until explicitly set to `enforce`. An `audit`-only policy will be logged but NOT blocked.",
			Resource:       scanner.Resource{Kind: "Cluster", Name: "kyverno"},
			Recommendation: "kubectl get cpol,pol -A -o json | jq '.items[] | {name:.metadata.name, validationFailureAction:.spec.validationFailureAction}'",
			References:     []string{"https://kyverno.io/docs/writing-policies/validate/#validation-failure-action"},
		})
	}
	return out
}

func isKnownSystemController(name string) bool {
	low := strings.ToLower(name)
	for _, sys := range []string{
		"cert-manager",
		"kube-system",
		"validating",
		"cluster-autoscaler",
		"aws-load-balancer",
		"istio",
		"linkerd",
		"kyverno",
		"gatekeeper",
	} {
		if strings.Contains(low, sys) {
			return true
		}
	}
	return false
}
