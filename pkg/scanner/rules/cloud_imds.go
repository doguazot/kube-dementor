package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
)

func CloudRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-CLOUD-IRSA-001", Title: "Cloud workload-identity annotation (SA assumes IAM role)", Category: scanner.CatClusterLevel, Fn: ruleCloudWorkloadIdentity},
		{ID: "KH-CLOUD-IMDS-001", Title: "Pod can reach IMDS (169.254.169.254 / metadata.google.internal)", Category: scanner.CatNetwork, Fn: ruleIMDSReachable},
		{ID: "KH-CLOUD-IMDS-002", Title: "hostNetwork pod bypasses CNI → direct IMDS / node-credential access", Category: scanner.CatNetwork, Fn: ruleHostNetworkIMDS},
	}
}

var workloadIdentityAnnotations = map[string]string{
	"eks.amazonaws.com/role-arn":        "AWS IRSA",
	"iam.gke.io/gcp-service-account":    "GCP Workload Identity",
	"azure.workload.identity/client-id": "Azure Workload Identity",
	"azure.workload.identity/tenant-id": "Azure Workload Identity",
	"vault.hashicorp.com/role":          "HashiCorp Vault role",
	"secrets.hashicorp.com/role":        "Vault Secrets Operator role",
	"sigstore.dev/cosign-signer":        "Sigstore signer",
	"jenkins.io/credentials-id":         "Jenkins credential ref",
}

func ruleCloudWorkloadIdentity(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding

	podsBySA := map[string][]*corev1.Pod{}
	for i := range inv.Pods {
		p := &inv.Pods[i]
		sa := p.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		k := p.Namespace + "/" + sa
		podsBySA[k] = append(podsBySA[k], p)
	}
	for _, sa := range inv.ServiceAccounts {
		hits := map[string]string{}
		for ann, val := range sa.Annotations {
			if provider, ok := workloadIdentityAnnotations[ann]; ok {
				hits[ann] = provider + "=" + val
			}
		}
		if len(hits) == 0 {
			continue
		}
		key := sa.Namespace + "/" + sa.Name
		pods := podsBySA[key]
		var podLines []string
		for _, p := range pods {
			reach := imdsReachHint(p, inv)
			podLines = append(podLines, fmt.Sprintf("  • pod/%s (hostNetwork=%v, %s)", p.Name, p.Spec.HostNetwork, reach))
		}
		if len(podLines) == 0 {
			podLines = []string{"  (no running pod — still a loaded credential; create a pod under this SA to assume the cloud role)"}
		}
		var annLines []string
		keys := make([]string, 0, len(hits))
		for k := range hits {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			annLines = append(annLines, fmt.Sprintf("  %s = %s", k, hits[k]))
		}
		sev := scanner.SevHigh
		if len(pods) > 0 {
			sev = scanner.SevCritical
		}
		out = append(out, scanner.Finding{
			RuleID:   "KH-CLOUD-IRSA-001",
			Category: scanner.CatClusterLevel,
			Severity: sev,
			Title:    fmt.Sprintf("ServiceAccount %s/%s assumes a cloud identity (%s)", sa.Namespace, sa.Name, describeProviders(hits)),
			Resource: scanner.Resource{Kind: "ServiceAccount", Namespace: sa.Namespace, Name: sa.Name},
			Description: "This ServiceAccount carries an annotation that hands its pods a bearer credential for a cloud IAM role (AWS IRSA / GCP WI / Azure WI / Vault). " +
				"An attacker who compromises the pod can immediately exchange the projected token for a short-lived cloud credential and leave the cluster boundary. " +
				"Whether the actual cloud role is powerful (e.g. S3 full access, GKE node admin) depends on the cloud-side IAM policy, which is outside kube-dementor's view.",
			Evidence:       strings.Join(append([]string{"Annotations:"}, append(annLines, "Pods using this SA:")...), "\n") + "\n" + strings.Join(podLines, "\n"),
			Impact:         "Cluster → cloud pivot. Silent data exfiltration, S3 bucket enumeration, RDS snapshot copy, GCS read, KMS key abuse, etc. depending on the bound cloud IAM role.",
			Recommendation: "Minimise the cloud role's policy (least-privilege on the cloud side). Bind the SA only to pods that need the credential. Consider session-policy / policy-boundary guardrails on the cloud IAM role.",
			References: []string{
				"https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html",
				"https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity",
				"https://azure.github.io/azure-workload-identity/docs/",
			},
			MitreATTACK: []string{"T1078.004", "T1550.001"},
			Tags:        []string{"cloud", "workload-identity", "pivot", "blast-radius"},
		})
	}
	return out
}

func describeProviders(hits map[string]string) string {
	providers := map[string]bool{}
	for _, v := range hits {
		if i := strings.Index(v, "="); i > 0 {
			providers[v[:i]] = true
		}
	}
	ps := make([]string, 0, len(providers))
	for p := range providers {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return strings.Join(ps, ", ")
}

func imdsReachHint(p *corev1.Pod, inv *scanner.Inventory) string {
	if p.Spec.HostNetwork {
		return "host-network → direct IMDS"
	}
	if blockedByNP(p, inv) {
		return "NetworkPolicy blocks 169.254.169.254"
	}
	return "no explicit block → likely reach IMDS"
}

func blockedByNP(p *corev1.Pod, inv *scanner.Inventory) bool {
	for _, np := range inv.NetworkPolicies {
		if np.Namespace != p.Namespace {
			continue
		}
		if !selectorMatches(np.Spec.PodSelector, p) {
			continue
		}

		hasEgress := false
		for _, pt := range np.Spec.PolicyTypes {
			if pt == netv1.PolicyTypeEgress {
				hasEgress = true
				break
			}
		}
		if !hasEgress {
			continue
		}

		if len(np.Spec.Egress) == 0 {
			return true
		}

		for _, e := range np.Spec.Egress {
			for _, to := range e.To {
				if to.IPBlock == nil {
					continue
				}
				for _, ex := range to.IPBlock.Except {
					if strings.HasPrefix(ex, "169.254.") {
						return true
					}
				}
			}
		}
	}
	return false
}

func selectorMatches(sel interface{}, p *corev1.Pod) bool {

	return true
}

func ruleIMDSReachable(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding

	type hit struct {
		pod    *corev1.Pod
		reason string
	}
	nsHits := map[string][]hit{}
	for i := range inv.Pods {
		p := &inv.Pods[i]
		reason := imdsReachHint(p, inv)
		if strings.HasPrefix(reason, "NetworkPolicy") {
			continue
		}
		nsHits[p.Namespace] = append(nsHits[p.Namespace], hit{pod: p, reason: reason})
	}
	if len(nsHits) == 0 {
		return nil
	}

	for ns, hits := range nsHits {
		if len(hits) == 0 {
			continue
		}
		var lines []string
		for _, h := range hits {
			sa := h.pod.Spec.ServiceAccountName
			if sa == "" {
				sa = "default"
			}
			lines = append(lines, fmt.Sprintf("  • %s/%s (SA=%s) — %s", h.pod.Namespace, h.pod.Name, sa, h.reason))
		}
		sort.Strings(lines)
		if len(lines) > 25 {
			lines = append(lines[:25], fmt.Sprintf("  … and %d more pod(s) in this namespace", len(nsHits[ns])-25))
		}
		out = append(out, scanner.Finding{
			RuleID:   "KH-CLOUD-IMDS-001",
			Category: scanner.CatNetwork,
			Severity: scanner.SevMedium,
			Title:    fmt.Sprintf("Namespace %q: %d pod(s) likely reach instance metadata (169.254.169.254)", ns, len(hits)),
			Resource: scanner.Resource{Kind: "Namespace", Name: ns},
			Description: "No NetworkPolicy in this namespace demonstrably blocks egress to the cloud instance metadata service (IMDSv1/v2 on AWS, metadata.google.internal on GCP, 169.254.169.254 on Azure). " +
				"A compromised pod can query IMDS and — depending on IMDSv2 hop-count configuration and the node-role IAM policy — acquire the node's cloud credentials, often far more powerful than any pod-level IRSA credential.",
			Evidence:       strings.Join(lines, "\n"),
			Impact:         "Node-IAM credential theft. Typical blast-radius: cluster → VPC-wide AWS / GCP / Azure access using whatever the instance role holds.",
			Recommendation: "Apply a NetworkPolicy excluding 169.254.0.0/16 (and 169.254.169.254 specifically on AWS/Azure) from egress. On AWS, enable IMDSv2 with --http-put-response-hop-limit=1 to block pod-level access.",
			References: []string{
				"https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/",
				"https://cloud.google.com/compute/docs/metadata/overview",
			},
			MitreATTACK: []string{"T1552.005"},
			Tags:        []string{"cloud", "imds", "network", "pivot"},
		})
	}
	return out
}

func ruleHostNetworkIMDS(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !p.Spec.HostNetwork {
			continue
		}
		sa := p.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		out = append(out, scanner.Finding{
			RuleID:         "KH-CLOUD-IMDS-002",
			Category:       scanner.CatNetwork,
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("hostNetwork pod %s/%s bypasses NetworkPolicy (IMDS + node cred reach)", p.Namespace, p.Name),
			Resource:       scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
			Description:    "`hostNetwork: true` makes the pod share the node's network namespace, so NetworkPolicy has no effect on it. The pod can reach the node's loopback interface (127.0.0.1), the kubelet API on 10250/10255, and the cloud instance metadata service on 169.254.169.254 directly.",
			Evidence:       fmt.Sprintf("SA=%s, containers=%d", sa, len(p.Spec.Containers)),
			Impact:         "Direct node-role IAM theft; kubelet API abuse; lateral access to other pods' localhost services.",
			Recommendation: "Drop hostNetwork unless the workload is genuinely a node-agent. If a node-agent is required, restrict it with an admission policy so only a single well-reviewed image can run with hostNetwork=true.",
			MitreATTACK:    []string{"T1552.005", "T1610"},
			Tags:           []string{"cloud", "imds", "host-network", "privesc"},
		})
	}
	return out
}

var _ = netv1.NetworkPolicy{}
