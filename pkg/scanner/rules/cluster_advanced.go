package rules

import (
	"fmt"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func ClusterAdvancedRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-CLU-004", Title: "etcd exposed or misconfigured", Category: scanner.CatClusterLevel, Fn: ruleCLU004Etcd},
		{ID: "KH-CLU-005", Title: "API Server insecure port", Category: scanner.CatClusterLevel, Fn: ruleCLU005InsecurePort},
		{ID: "KH-PERSIST-STATIC-POD", Title: "Static pod detected (no controller)", Category: scanner.CatPersistence, Fn: rulePersistStaticPod},
	}
}

func ruleCLU004Etcd(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding

	for _, p := range inv.Pods {
		name := strings.ToLower(p.Name)
		if !strings.Contains(name, "etcd") {
			continue
		}

		for _, c := range p.Spec.Containers {
			args := strings.Join(c.Args, " ") + " " + strings.Join(c.Command, " ")
			hasClientCert := strings.Contains(args, "--client-cert-auth") ||
				strings.Contains(args, "--peer-client-cert-auth")
			hasHTTPS := strings.Contains(args, "https://")

			if !hasClientCert {
				out = append(out, scanner.Finding{
					Severity: scanner.SevCritical,
					Title:    fmt.Sprintf("etcd pod %s/%s missing --client-cert-auth", p.Namespace, p.Name),
					Description: "The etcd pod does not appear to have --client-cert-auth enabled. Without client certificate authentication, " +
						"any client that can reach etcd can read and write ALL cluster state including Secrets, RBAC rules, and pod specs.",
					Resource: scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
					Evidence: fmt.Sprintf("Container %s args: %s (no --client-cert-auth found)", c.Name, truncStr(args, 200)),
					Impact:   "Full cluster compromise. etcd contains every Secret (including SA tokens, TLS certs), every RBAC rule, and every workload spec.",
					Recommendation: "Enable --client-cert-auth=true on etcd. Ensure --trusted-ca-file and --cert-file/--key-file are set. " +
						"Restrict network access to etcd to control-plane components only.",
					References: []string{
						"https://etcd.io/docs/v3.5/op-guide/security/",
						"https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/#securing-etcd-clusters",
					},
					MitreATTACK: []string{"T1552"},
					Tags:        []string{"etcd", "authentication", "cluster-state"},
				})
			}

			if !hasHTTPS {
				out = append(out, scanner.Finding{
					Severity: scanner.SevCritical,
					Title:    fmt.Sprintf("etcd pod %s/%s may accept plaintext HTTP connections", p.Namespace, p.Name),
					Description: "The etcd pod does not appear to use HTTPS for client connections. Without TLS, etcd traffic " +
						"(including Secrets and SA tokens) travels unencrypted on the network.",
					Resource: scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
					Evidence: fmt.Sprintf("Container %s args do not contain https:// listen address", c.Name),
					Impact:   "Network-level interception of all cluster state. Any pod or process on the node network can sniff etcd traffic.",
					Recommendation: "Configure etcd to use TLS: set --listen-client-urls and --advertise-client-urls to https:// addresses. " +
						"Set --cert-file and --key-file for the server certificate.",
					Tags: []string{"etcd", "encryption", "tls"},
				})
			}
		}

		if p.Namespace != "kube-system" && p.Namespace != "etcd-system" {
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          fmt.Sprintf("etcd pod running outside kube-system: %s/%s", p.Namespace, p.Name),
				Description:    "etcd is running in a non-system namespace. This may indicate a misconfiguration or a rogue etcd deployment.",
				Resource:       scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
				Recommendation: "Run etcd only in kube-system or a dedicated etcd-system namespace with strict RBAC.",
				Tags:           []string{"etcd", "namespace"},
			})
		}
	}

	for _, s := range inv.Services {
		name := strings.ToLower(s.Name)
		if !strings.Contains(name, "etcd") {
			continue
		}

		if s.Spec.Type == "NodePort" || s.Spec.Type == "LoadBalancer" {
			out = append(out, scanner.Finding{
				Severity: scanner.SevCritical,
				Title:    fmt.Sprintf("etcd service %s/%s exposed via %s", s.Namespace, s.Name, s.Spec.Type),
				Description: fmt.Sprintf("The etcd service is exposed as %s, making it reachable from outside the cluster. "+
					"etcd contains the entire cluster state including all Secrets.", s.Spec.Type),
				Resource:       scanner.Resource{Kind: "Service", Namespace: s.Namespace, Name: s.Name},
				Impact:         "Remote access to ALL cluster data. Full cluster compromise.",
				Recommendation: "Change the etcd service to ClusterIP. etcd should only be accessible from the API server.",
				Tags:           []string{"etcd", "exposure", "network"},
			})
		}

		for _, port := range s.Spec.Ports {
			if port.Port == 2379 || port.Port == 2380 {
				out = append(out, scanner.Finding{
					Severity: scanner.SevHigh,
					Title:    fmt.Sprintf("etcd client port %d exposed via service %s/%s", port.Port, s.Namespace, s.Name),
					Description: fmt.Sprintf("etcd port %d is exposed through a Kubernetes Service. "+
						"Port 2379 is the client API, port 2380 is the peer API.", port.Port),
					Resource:       scanner.Resource{Kind: "Service", Namespace: s.Namespace, Name: s.Name},
					Evidence:       fmt.Sprintf("Service port: %d → target %d", port.Port, port.TargetPort.IntValue()),
					Impact:         "Any pod with network access to this service can interact with etcd directly.",
					Recommendation: "Restrict etcd access to control-plane components via NetworkPolicy. Use mTLS for all etcd connections.",
					Tags:           []string{"etcd", "port", "network"},
				})
			}
		}
	}

	return out
}

func ruleCLU005InsecurePort(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding

	for _, p := range inv.Pods {
		name := strings.ToLower(p.Name)
		if !strings.Contains(name, "kube-apiserver") {
			continue
		}
		for _, c := range p.Spec.Containers {
			args := strings.Join(c.Args, " ") + " " + strings.Join(c.Command, " ")

			if strings.Contains(args, "--insecure-port") && !strings.Contains(args, "--insecure-port=0") {
				out = append(out, scanner.Finding{
					Severity: scanner.SevCritical,
					Title:    fmt.Sprintf("API Server %s/%s has insecure port enabled", p.Namespace, p.Name),
					Description: "The Kubernetes API Server is configured with --insecure-port (not set to 0). " +
						"The insecure port serves the full API without any authentication or authorization checks.",
					Resource:       scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
					Evidence:       fmt.Sprintf("Args: %s", truncStr(args, 300)),
					Impact:         "Anyone with network access to the insecure port has full cluster-admin access without authentication.",
					Recommendation: "Set --insecure-port=0 on the API Server. This flag is deprecated since Kubernetes 1.13 and removed in 1.20+.",
					References: []string{
						"https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/",
					},
					MitreATTACK: []string{"T1190"},
					Tags:        []string{"apiserver", "insecure-port", "authentication"},
				})
			}

			if strings.Contains(args, "--anonymous-auth=true") || (!strings.Contains(args, "--anonymous-auth") && strings.Contains(name, "kube-apiserver")) {

				if strings.Contains(args, "--anonymous-auth=true") {
					out = append(out, scanner.Finding{
						Severity: scanner.SevHigh,
						Title:    fmt.Sprintf("API Server %s/%s has anonymous authentication explicitly enabled", p.Namespace, p.Name),
						Description: "The API Server has --anonymous-auth=true set explicitly. While this is the default, " +
							"it allows unauthenticated requests to reach the API server. Combined with RBAC grants to system:anonymous, " +
							"this can expose cluster data.",
						Resource:       scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
						Recommendation: "Set --anonymous-auth=false unless there is a specific requirement. Review RBAC grants to system:anonymous and system:unauthenticated.",
						Tags:           []string{"apiserver", "anonymous", "authentication"},
					})
				}
			}

			if !strings.Contains(args, "--audit-log-path") && !strings.Contains(args, "--audit-webhook-config-file") {
				out = append(out, scanner.Finding{
					Severity: scanner.SevMedium,
					Title:    fmt.Sprintf("API Server %s/%s has no audit logging configured", p.Namespace, p.Name),
					Description: "The API Server does not have --audit-log-path or --audit-webhook-config-file configured. " +
						"Without audit logging, API server actions (including credential access, RBAC changes, and exec commands) " +
						"are not recorded.",
					Resource:       scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
					Impact:         "No audit trail for API server operations. Attackers can operate without detection.",
					Recommendation: "Enable audit logging with --audit-log-path and --audit-policy-file. Forward logs to a SIEM.",
					References: []string{
						"https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
					},
					Tags: []string{"apiserver", "audit", "logging"},
				})
			}
		}
	}
	return out
}

func rulePersistStaticPod(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding

	for _, p := range inv.Pods {

		if len(p.OwnerReferences) > 0 {
			continue
		}

		_, isMirror := p.Annotations["kubernetes.io/config.mirror"]
		_, hasSource := p.Annotations["kubernetes.io/config.source"]

		if !isMirror && !hasSource {

			continue
		}

		sev := scanner.SevMedium
		impact := "Static pods bypass API-level admission controllers and persist on the node even if deleted from the API. An attacker with node access can create persistent backdoor pods."

		isPriv := false
		for _, c := range p.Spec.Containers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				isPriv = true
				sev = scanner.SevHigh
				break
			}
		}
		if p.Spec.HostPID || p.Spec.HostNetwork {
			sev = scanner.SevHigh
		}

		desc := fmt.Sprintf("Pod %s/%s is a static pod (created by kubelet from a local manifest, not by a controller). ", p.Namespace, p.Name)
		if isPriv {
			desc += "The static pod runs with privileged: true, making it a high-value persistence vector."
		} else {
			desc += "Static pods bypass admission controllers and survive API-level deletion."
		}

		out = append(out, scanner.Finding{
			Severity:    sev,
			Title:       fmt.Sprintf("Static pod detected: %s/%s", p.Namespace, p.Name),
			Description: desc,
			Resource:    scanner.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
			Evidence: fmt.Sprintf("Pod has no ownerReferences. Annotations: mirror=%v, source=%v. "+
				"hostPID=%v hostNetwork=%v privileged=%v",
				isMirror, hasSource, p.Spec.HostPID, p.Spec.HostNetwork, isPriv),
			Impact: impact,
			Recommendation: "Audit static pod manifests in /etc/kubernetes/manifests/ on each node. " +
				"Ensure only expected control-plane components (kube-apiserver, kube-controller-manager, kube-scheduler, etcd) " +
				"are present. Monitor the manifest directory for changes via file integrity monitoring (FIM).",
			MitreATTACK: []string{"T1053", "T1543"},
			Tags:        []string{"persistence", "static-pod", "kubelet"},
		})
	}
	return out
}

func truncStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
