package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func RuntimeRulesStatic(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	out = append(out, runtimeEnvSecretHarvest(inv)...)
	out = append(out, runtimeServiceMeshAudit(inv)...)
	return out
}

var (
	credRegexes = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"aws_access_key_id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"aws_secret_key_env_hint", regexp.MustCompile(`(?i)(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)`)},
		{"gcp_sa_json_hint", regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`)},
		{"azure_client_secret_hint", regexp.MustCompile(`(?i)(AZURE_CLIENT_SECRET|AZURE_TENANT_ID)`)},
		{"github_token", regexp.MustCompile(`ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}`)},
		{"slack_token", regexp.MustCompile(`xox[bpoar]-[A-Za-z0-9-]{10,}`)},
		{"private_key", regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`)},
		{"generic_secret_name", regexp.MustCompile(`(?i)(password|passwd|secret|apikey|api_key|token)=.+`)},
	}
)

func runtimeEnvSecretHarvest(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range append(p.Spec.Containers, p.Spec.InitContainers...) {
			for _, e := range c.Env {

				if e.ValueFrom != nil {
					continue
				}
				val := e.Value
				name := e.Name
				for _, r := range credRegexes {
					if r.re.MatchString(val) || r.re.MatchString(name+"="+val) {
						sev := scanner.SevHigh
						if strings.Contains(r.name, "aws_access") || r.name == "private_key" {
							sev = scanner.SevCritical
						}
						poc := fmt.Sprintf(`# Quick test — does this credential still work?
# AWS:
export AWS_ACCESS_KEY_ID=<from env>
export AWS_SECRET_ACCESS_KEY=<from env>
aws sts get-caller-identity
# GCP:
echo <env json> > /tmp/sa.json && gcloud auth activate-service-account --key-file=/tmp/sa.json
gcloud projects list`)
						out = append(out, scanner.Finding{
							RuleID:         "KH-RUNTIME-001",
							Category:       scanner.CatRuntime,
							Severity:       sev,
							Title:          fmt.Sprintf("Credential in pod env var: %s matches %s", name, r.name),
							Description:    "A container's environment variable holds a literal credential. Anyone with pods/exec, pods/log (for echoed envs), or pod/get on this namespace can harvest it. Plaintext env-var secrets are the #1 source of cloud-account compromise from Kubernetes.",
							Resource:       scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
							Evidence:       fmt.Sprintf("container=%s env=%s pattern=%s", c.Name, name, r.name),
							Impact:         "Cloud-account / third-party-API credential theft via a single pod read.",
							Recommendation: `Move the value to a Secret + EnvFrom (still not great), or better: use a CSI secret driver (External Secrets / CSI SecretStore / IRSA / Workload Identity).`,
							Tags:           []string{"runtime", "credential-leak", r.name},
							Exploit: &scanner.ExploitResult{
								Attempted:   false,
								Verified:    true,
								SafetyLevel: "READ_ONLY",
								Evidence:    "Static pattern match in pod .spec.containers[].env[].value",
								PoC:         poc,
							},
						})
						break
					}
				}
			}
		}
	}
	return out
}

func runtimeServiceMeshAudit(inv *scanner.Inventory) []scanner.Finding {
	var out []scanner.Finding
	meshes := map[string]string{}
	sidecarPods := 0
	for _, p := range inv.Pods {
		for _, c := range append(p.Spec.Containers, p.Spec.InitContainers...) {
			img := strings.ToLower(c.Image)
			switch {
			case strings.Contains(img, "istio/proxyv2"), strings.Contains(img, "istio/pilot"),
				strings.Contains(img, "docker.io/istio"):
				meshes["Istio"] = "istio-system"
				sidecarPods++
			case strings.Contains(img, "linkerd/proxy"), strings.Contains(img, "linkerd/controller"):
				meshes["Linkerd"] = "linkerd"
				sidecarPods++
			case strings.Contains(img, "consul-k8s"), strings.Contains(img, "hashicorp/consul"):
				meshes["Consul Connect"] = "consul"
				sidecarPods++
			}
		}
	}

	for name, ns := range meshes {
		poc := ""
		rec := ""
		switch name {
		case "Istio":
			poc = `kubectl get peerauthentication -A -o json | jq '.items[] | {ns:.metadata.namespace, name:.metadata.name, mode:.spec.mtls.mode}'
# If any entry shows mode=PERMISSIVE or UNSET → plaintext is still accepted.
# Abuse: spin a pod without a sidecar and call target services directly:
kubectl run attacker --image=curlimages/curl -- sleep 3600
kubectl exec attacker -- curl -v http://<target-svc>.<ns>:80/`
			rec = "Switch mesh-wide default to STRICT (`meshConfig.defaultConfig.tls.mode: STRICT`); create a PeerAuthentication with mode=STRICT at the istio-system level."
		case "Linkerd":
			poc = `linkerd viz authz -n <ns>  # lists allowed servers
# Linkerd proxies enforce mTLS by default but HTTPRoute/ServerAuthorization gaps can bypass.`
			rec = "Enforce Server + ServerAuthorization for every meshed workload; audit unmeshed pods that can still reach the VIP."
		}
		out = append(out, scanner.Finding{
			RuleID:   "KH-RUNTIME-002",
			Category: scanner.CatServiceMesh,
			Severity: scanner.SevMedium,
			Title:    fmt.Sprintf("%s service mesh detected — audit mTLS mode", name),
			Description: fmt.Sprintf("%d pods run a %s sidecar. If the mesh-wide default is PERMISSIVE (Istio) or Linkerd policies aren't explicit, an unmeshed attacker pod can bypass mTLS by going to the clusterIP directly — defeating the whole point of the mesh.",
				sidecarPods, name),
			Resource:       scanner.Resource{Kind: "Cluster", Namespace: ns, Name: name},
			Evidence:       fmt.Sprintf("%d pods have %s sidecar images", sidecarPods, name),
			Impact:         "mTLS bypass / unmeshed lateral movement.",
			Recommendation: rec,
			Tags:           []string{"runtime", "service-mesh", strings.ToLower(name)},
			Exploit: &scanner.ExploitResult{
				Attempted:   false,
				Verified:    true,
				SafetyLevel: "READ_ONLY",
				PoC:         poc,
			},
		})
	}
	return out
}
