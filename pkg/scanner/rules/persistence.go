package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	admissionv1 "k8s.io/api/admissionregistration/v1"
)

func PersistenceRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-PERSIST-MWHC-WIDE", Title: "MutatingWebhookConfiguration matches a wide resource scope", Category: scanner.CatPersistence, Fn: rulePersistMutatingWide},
		{ID: "KH-PERSIST-VWHC-WIDE", Title: "ValidatingWebhookConfiguration matches a wide resource scope", Category: scanner.CatPersistence, Fn: rulePersistValidatingWide},
		{ID: "KH-PERSIST-WEBHOOK-FAIL-OPEN", Title: "Admission webhook fails open (failurePolicy=Ignore)", Category: scanner.CatPersistence, Fn: rulePersistFailOpen},
		{ID: "KH-PERSIST-CRONJOB-PRIV", Title: "CronJob runs a privileged / hostPath / hostPID workload", Category: scanner.CatPersistence, Fn: rulePersistCronJobPrivileged},
		{ID: "KH-PERSIST-CRONJOB-OFF-HOURS", Title: "CronJob scheduled outside business hours into a system namespace", Category: scanner.CatPersistence, Fn: rulePersistCronJobOffHours},
		{ID: "KH-PERSIST-JOB-LONG-LIVED", Title: "Job has run-time / restart pattern compatible with persistent backdoor", Category: scanner.CatPersistence, Fn: rulePersistJobLongLived},
		{ID: "KH-PERSIST-INIT-IMAGE-EXTERNAL", Title: "InitContainer pulls from a non-corporate registry", Category: scanner.CatPersistence, Fn: rulePersistInitExternal},
		{ID: "KH-PERSIST-DAEMONSET-HOSTROOT", Title: "DaemonSet mounts hostPath:/ — node-wide foothold candidate", Category: scanner.CatPersistence, Fn: rulePersistDaemonSetHostRoot},
		{ID: "KH-PERSIST-DEPLOY-IMG-MUTABLE", Title: "Deployment uses mutable tag (latest / no digest) → registry hijack persistence", Category: scanner.CatPersistence, Fn: rulePersistMutableImageTag},
	}
}

func webhookHasWideScope(rs []admissionv1.RuleWithOperations) bool {
	for _, r := range rs {
		for _, g := range r.APIGroups {
			if g == "*" {
				return true
			}
		}
		for _, res := range r.Resources {
			if res == "*" || res == "*/*" {
				return true
			}
			if res == "pods" || res == "pods/exec" {

			}
		}
		for _, op := range r.Operations {
			if op == "*" {
				return true
			}
		}
	}
	return false
}

func rulePersistMutatingWide(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, m := range inv.MutatingWebhooks {

		if isWellKnownAdmissionPlugin(m.Name) {
			continue
		}
		for _, w := range m.Webhooks {
			if !webhookHasWideScope(w.Rules) {
				continue
			}
			endpoint := webhookEndpoint(w.ClientConfig)
			out = append(out, scanner.Finding{
				Severity:       scanner.SevHigh,
				Title:          fmt.Sprintf("MutatingWebhookConfiguration %q has wildcard scope (potential persistence vector)", m.Name),
				Description:    "Webhook rule contains `*` for groups/resources/operations. An attacker who can edit this webhook can inject a sidecar, env var, command override, or a malicious initContainer into every pod created cluster-wide. Many real-world supply-chain attacks plant a hidden MutatingWebhook that injects a reverse-shell sidecar.",
				Resource:       scanner.Resource{Kind: "MutatingWebhookConfiguration", Name: m.Name},
				Evidence:       fmt.Sprintf("webhook=%s endpoint=%s rules=%v", w.Name, endpoint, w.Rules),
				Impact:         "Cluster-wide RCE on every pod the webhook intercepts. Severity: cluster-admin equivalent persistence.",
				Recommendation: "Scope the webhook rules to the exact resource/api-group/op. Audit who can `update` this MWHC. Consider Pod Security Admission for plain pod policy.",
				Tags:           []string{"persistence", "admission", "mutating-webhook"},
			})
		}
	}
	return out
}

func rulePersistValidatingWide(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, v := range inv.ValidatingWebhooks {
		if isWellKnownAdmissionPlugin(v.Name) {
			continue
		}
		for _, w := range v.Webhooks {
			if !webhookHasWideScope(w.Rules) {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevMedium,
				Title:          fmt.Sprintf("ValidatingWebhookConfiguration %q has wildcard scope", v.Name),
				Description:    "Although a ValidatingWebhook cannot mutate, an attacker who can update it can shape *what is allowed* in the cluster — silencing PSA / OPA / Kyverno rules by overriding their decisions, or selectively rejecting only legitimate workloads to mask their own.",
				Resource:       scanner.Resource{Kind: "ValidatingWebhookConfiguration", Name: v.Name},
				Evidence:       fmt.Sprintf("webhook=%s rules=%v", w.Name, w.Rules),
				Impact:         "Stealth privilege manipulation: bypass other admission controllers; reject competing CI deployments to evade detection.",
				Recommendation: "Scope rules to the smallest resource set. Audit `update validatingwebhookconfigurations`.",
				Tags:           []string{"persistence", "admission", "validating-webhook"},
			})
		}
	}
	return out
}

func rulePersistFailOpen(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	check := func(kind, name string, fp *admissionv1.FailurePolicyType) {
		if fp == nil || *fp != admissionv1.Ignore {
			return
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("%s %q fails open (failurePolicy=Ignore)", kind, name),
			Description:    "When the webhook server is unreachable the API server **proceeds without calling it**. An attacker who can DoS or partition the webhook pod has effectively disabled the policy check it implements (PSA, OPA Gatekeeper, Kyverno).",
			Resource:       scanner.Resource{Kind: kind, Name: name},
			Evidence:       "failurePolicy=Ignore",
			Impact:         "Policy evasion. Kill the webhook pod or block its NetworkPolicy → admission proceeds; arbitrary privileged pods can be created.",
			Recommendation: "Set failurePolicy=Fail (default since 1.16). Use HA replicas + pod-disruption-budget for the webhook itself so Fail mode does not break legitimate traffic.",
			Tags:           []string{"persistence", "admission", "fail-open"},
		})
	}
	for _, m := range inv.MutatingWebhooks {
		for _, w := range m.Webhooks {
			check("MutatingWebhookConfiguration", m.Name, w.FailurePolicy)
		}
	}
	for _, v := range inv.ValidatingWebhooks {
		for _, w := range v.Webhooks {
			check("ValidatingWebhookConfiguration", v.Name, w.FailurePolicy)
		}
	}
	return out
}

func isWellKnownAdmissionPlugin(name string) bool {
	for _, prefix := range []string{
		"istio", "cert-manager", "kyverno", "gatekeeper",
		"linkerd", "kube-prometheus", "metrics-server",
		"snapshot.storage", "policy.cilium.io", "vmware",
		"calico", "csi-snapshot", "rancher",
	} {
		if strings.Contains(name, prefix) {
			return true
		}
	}
	return false
}

func webhookEndpoint(c admissionv1.WebhookClientConfig) string {
	if c.URL != nil {
		return *c.URL
	}
	if c.Service != nil {
		path := ""
		if c.Service.Path != nil {
			path = *c.Service.Path
		}
		return fmt.Sprintf("%s/%s%s", c.Service.Namespace, c.Service.Name, path)
	}
	return "(unknown)"
}

func rulePersistCronJobPrivileged(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, cj := range inv.CronJobs {
		spec := cj.Spec.JobTemplate.Spec.Template.Spec
		var reasons []string
		if spec.HostNetwork {
			reasons = append(reasons, "hostNetwork")
		}
		if spec.HostPID {
			reasons = append(reasons, "hostPID")
		}
		for _, c := range append(spec.Containers, spec.InitContainers...) {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				reasons = append(reasons, "privileged="+c.Name)
			}
		}
		for _, v := range spec.Volumes {
			if v.HostPath != nil {
				reasons = append(reasons, "hostPath="+v.HostPath.Path)
			}
		}
		if len(reasons) == 0 {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("CronJob %s/%s runs a privileged workload on schedule %q", cj.Namespace, cj.Name, cj.Spec.Schedule),
			Description:    "A privileged CronJob is the textbook persistent-foothold mechanism in Kubernetes. Even after the operator deletes a malicious pod, the next firing of the schedule re-creates it with the same privileges.",
			Resource:       scanner.Resource{Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name},
			Evidence:       fmt.Sprintf("schedule=%s reasons=%s", cj.Spec.Schedule, strings.Join(reasons, ",")),
			Impact:         "Re-establishes node-level access on every schedule firing. Forensic responders need to delete the CronJob, not just the running pod.",
			Recommendation: "Audit the CronJob: is its image, command and schedule legitimate? If yes, drop privileges. If not, delete the CronJob and rotate the SA it uses.",
			Tags:           []string{"persistence", "cronjob"},
		})
	}
	return out
}

func rulePersistCronJobOffHours(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, cj := range inv.CronJobs {
		s := cj.Spec.Schedule

		looksOffHours := false
		if strings.HasPrefix(s, "* * * * *") || strings.HasPrefix(s, "*/1 * * * *") || strings.HasPrefix(s, "*/5 * * * *") {
			looksOffHours = true
		}

		isSysNs := strings.HasPrefix(cj.Namespace, "kube-") || cj.Namespace == "default"
		if !looksOffHours && !isSysNs {
			continue
		}
		if !looksOffHours {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("CronJob %s/%s fires every minute / few minutes — review necessity", cj.Namespace, cj.Name),
			Description:    "Every-minute CronJobs are unusual outside of metrics agents. Attackers use this pattern to keep a reverse-shell warm. Review the image, command, and SA.",
			Resource:       scanner.Resource{Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name},
			Evidence:       fmt.Sprintf("schedule=%q", s),
			Impact:         "If malicious, ensures fast re-establishment of C2 even after pod kill.",
			Recommendation: "Justify the schedule. Move to event-driven processing or once-an-hour for legitimate batch work.",
			Tags:           []string{"persistence", "cronjob", "schedule"},
		})
	}
	return out
}

func rulePersistJobLongLived(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	now := time.Now()
	for _, j := range inv.Jobs {
		if j.Status.StartTime == nil {
			continue
		}
		age := now.Sub(j.Status.StartTime.Time)
		if age < 24*time.Hour {
			continue
		}
		if j.Status.Active == 0 {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("Job %s/%s has been running for %s without finishing", j.Namespace, j.Name, age.Truncate(time.Hour)),
			Description:    "Long-running Jobs that never complete are commonly used to host reverse shells and backdoor binaries — Job objects are simpler to forget about than Deployments and they don't show up in `kubectl get pods` once finished.",
			Resource:       scanner.Resource{Kind: "Job", Namespace: j.Namespace, Name: j.Name},
			Evidence:       fmt.Sprintf("startedAt=%s active=%d", j.Status.StartTime.Time.Format(time.RFC3339), j.Status.Active),
			Impact:         "Possible long-running C2 / dropper.",
			Recommendation: "Verify the Job's image and command. Job objects should set `activeDeadlineSeconds` to bound run-time.",
			Tags:           []string{"persistence", "job"},
		})
	}
	return out
}

func rulePersistInitExternal(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	corporateMarkers := []string{
		"docker.io/library/", "k8s.gcr.io", "registry.k8s.io",
		"quay.io", "ghcr.io",
	}
	internalMarkers := []string{}
	_ = internalMarkers
	for _, p := range inv.Pods {
		for _, c := range p.Spec.InitContainers {
			img := c.Image
			external := true

			for _, m := range corporateMarkers {
				if strings.Contains(img, m) {
					external = true
					break
				}
			}

			if !strings.Contains(img, "/") {
				external = true
			}

			lower := strings.ToLower(img)
			if strings.Contains(lower, "busybox") || strings.Contains(lower, "alpine") || strings.Contains(lower, "init") {
				continue
			}
			if !external {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevLow,
				Title:          fmt.Sprintf("InitContainer pulls a non-trivial external image on %s/%s (%s)", p.Namespace, p.Name, c.Name),
				Description:    "InitContainers run before the main app and have the same SA token mount. A malicious init image can drop a payload onto a shared volume or exfil the SA token before the workload even starts.",
				Resource:       podResource(p),
				Evidence:       fmt.Sprintf("init=%s image=%s", c.Name, img),
				Impact:         "Supply-chain & persistence: any compromise of the init image survives across pod restarts and is rarely audited.",
				Recommendation: "Pin to a digest, mirror the image into your private registry, scan it with Trivy.",
				Tags:           []string{"persistence", "init-container", "supply-chain"},
			})
		}
	}
	return out
}

func rulePersistDaemonSetHostRoot(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, ds := range inv.DaemonSets {
		spec := ds.Spec.Template.Spec
		for _, v := range spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			if v.HostPath.Path != "/" {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       scanner.SevCritical,
				Title:          fmt.Sprintf("DaemonSet %s/%s mounts hostPath:/ — node-wide persistent foothold", ds.Namespace, ds.Name),
				Description:    "A DaemonSet runs on every node. Mounting `/` from the host as a volume inside a DaemonSet means an attacker who controls one DaemonSet pod owns every node in the cluster. This is a textbook attacker-planted foothold.",
				Resource:       scanner.Resource{Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name},
				Evidence:       fmt.Sprintf("hostPath:/ via volume=%s", v.Name),
				Impact:         "Cluster-wide node compromise. Any update to the DaemonSet template propagates immediately to every node.",
				Recommendation: "Replace hostPath:/ with the smallest specific path needed. If this is a legitimate node-monitoring agent, document and reduce scope.",
				Tags:           []string{"persistence", "daemonset", "hostpath"},
			})
		}
	}
	return out
}

func rulePersistMutableImageTag(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	check := func(kind, ns, name, image, container string) {
		if image == "" {
			return
		}

		hasDigest := strings.Contains(image, "@sha256:")
		if hasDigest {
			return
		}
		mutable := false
		switch {
		case strings.HasSuffix(image, ":latest"):
			mutable = true
		case !strings.Contains(image, ":"):
			mutable = true
		case strings.HasSuffix(image, ":main") || strings.HasSuffix(image, ":master") ||
			strings.HasSuffix(image, ":dev") || strings.HasSuffix(image, ":stable"):
			mutable = true
		}
		if !mutable {
			return
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevMedium,
			Title:          fmt.Sprintf("%s %s/%s uses mutable image tag (no digest pin) on container %q", kind, ns, name, container),
			Description:    "Image tags like `:latest`, `:main`, or no tag at all are mutable. Anyone with push access to the registry can replace the artifact pointed to by the tag and the next pod restart will silently pull the new image — classic supply-chain persistence.",
			Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
			Evidence:       fmt.Sprintf("image=%s", image),
			Impact:         "Registry hijack persistence: backdoor the image once; every restart re-establishes the implant. Combined with `imagePullPolicy: Always` (the default for :latest), this fires on every pod restart.",
			Recommendation: "Pin to a content digest (image@sha256:...). Use `imagePullPolicy: IfNotPresent` and an immutable tag plus digest.",
			Tags:           []string{"persistence", "supply-chain", "mutable-tag"},
		})
	}
	for _, d := range inv.Deployments {
		for _, c := range d.Spec.Template.Spec.Containers {
			check("Deployment", d.Namespace, d.Name, c.Image, c.Name)
		}
	}
	for _, ds := range inv.DaemonSets {
		for _, c := range ds.Spec.Template.Spec.Containers {
			check("DaemonSet", ds.Namespace, ds.Name, c.Image, c.Name)
		}
	}
	for _, st := range inv.StatefulSets {
		for _, c := range st.Spec.Template.Spec.Containers {
			check("StatefulSet", st.Namespace, st.Name, c.Image, c.Name)
		}
	}
	return out
}
