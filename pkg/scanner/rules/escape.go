package rules

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func EscapeRules() []scanner.Rule {
	rules := []scanner.Rule{
		{ID: "KH-ESC-RUNC-2024-21626", Title: "runc CVE-2024-21626 — leaked fd container breakout (Leaky Vessels)", Category: scanner.CatEscape, Fn: ruleRuncLeakyVesselsCWD},
		{ID: "KH-ESC-RUNC-2024-23651", Title: "BuildKit CVE-2024-23651 — race in cache mount (Leaky Vessels)", Category: scanner.CatEscape, Fn: ruleBuildKitCacheRace},
		{ID: "KH-ESC-RUNC-2024-23652", Title: "BuildKit CVE-2024-23652 — host path traversal during build (Leaky Vessels)", Category: scanner.CatEscape, Fn: ruleBuildKitHostTraversal},
		{ID: "KH-ESC-RUNC-2024-23653", Title: "BuildKit CVE-2024-23653 — privileged container in build", Category: scanner.CatEscape, Fn: ruleBuildKitPrivileged},
		{ID: "KH-ESC-RUNC-2025-31133", Title: "runc CVE-2025-31133 — namespace mount bind escape", Category: scanner.CatEscape, Fn: ruleRunc2025_31133},
		{ID: "KH-ESC-RUNC-2025-52565", Title: "runc CVE-2025-52565 — bind-mount procfs override", Category: scanner.CatEscape, Fn: ruleRunc2025_52565},
		{ID: "KH-ESC-RUNC-2025-52881", Title: "runc CVE-2025-52881 — denial of service via gadget", Category: scanner.CatEscape, Fn: ruleRunc2025_52881},
		{ID: "KH-ESC-RUNC-2019-5736", Title: "runc CVE-2019-5736 — host runc binary overwrite via /proc/self/exe", Category: scanner.CatEscape, Fn: ruleRunc2019_5736},
		{ID: "KH-ESC-CTRD-2022-23648", Title: "containerd CVE-2022-23648 — image config rootfs symlink escape", Category: scanner.CatEscape, Fn: ruleContainerd2022_23648},
		{ID: "KH-ESC-CGROUP-2022-0492", Title: "Kernel CVE-2022-0492 — cgroup release_agent privilege escalation", Category: scanner.CatEscape, Fn: ruleCgroupReleaseAgent},
		{ID: "KH-ESC-FSCFG-2022-0185", Title: "Kernel CVE-2022-0185 — FS_CONFIG heap overflow → container escape", Category: scanner.CatEscape, Fn: ruleFsConfig2022_0185},
		{ID: "KH-ESC-DIRTYPIPE-2022-0847", Title: "Kernel CVE-2022-0847 — Dirty Pipe local privilege escalation", Category: scanner.CatEscape, Fn: ruleDirtyPipe2022_0847},
		{ID: "KH-ESC-NFTABLES-2024-1086", Title: "Kernel CVE-2024-1086 — nf_tables UAF local privilege escalation", Category: scanner.CatEscape, Fn: ruleNftables2024_1086},
		{ID: "KH-ESC-DIRTYCOW-2016-5195", Title: "Kernel CVE-2016-5195 — Dirty COW (legacy nodes only)", Category: scanner.CatEscape, Fn: ruleDirtyCow2016_5195},
		{ID: "KH-ESC-CORE-PATTERN", Title: "Writable /proc/sys/kernel/core_pattern → host RCE", Category: scanner.CatEscape, Fn: ruleCorePattern},
		{ID: "KH-ESC-PROCSELF-EXE", Title: "Writable /proc/self/exe path or shared host /usr/sbin/runc", Category: scanner.CatEscape, Fn: ruleProcSelfExe},
		{ID: "KH-ESC-PTRACE", Title: "SYS_PTRACE + shareProcessNamespace = cross-namespace process injection", Category: scanner.CatEscape, Fn: rulePtraceCrossNS},
		{ID: "KH-ESC-DEVCAP", Title: "MKNOD / SYS_RAWIO / SYS_MODULE / DAC_READ_SEARCH = device or module escape", Category: scanner.CatEscape, Fn: ruleDangerousDevCaps},
		{ID: "KH-ESC-CGROUP-MOUNT", Title: "Writable /sys/fs/cgroup mount → release_agent abuse", Category: scanner.CatEscape, Fn: ruleCgroupMount},
		{ID: "KH-ESC-DEV-MEM", Title: "Mounted /dev/mem or /dev/kmem → kernel memory access", Category: scanner.CatEscape, Fn: ruleDevMem},
		{ID: "KH-ESC-POSTURE", Title: "Container escape posture (cluster summary)", Category: scanner.CatEscape, Fn: ruleEscapePosture},
	}
	for i := range rules {
		switch rules[i].ID {
		case "KH-ESC-RUNC-2024-21626", "KH-ESC-RUNC-2025-31133",
			"KH-ESC-RUNC-2025-52565", "KH-ESC-RUNC-2025-52881",
			"KH-ESC-RUNC-2019-5736", "KH-ESC-CTRD-2022-23648",
			"KH-ESC-FSCFG-2022-0185", "KH-ESC-DIRTYPIPE-2022-0847",
			"KH-ESC-NFTABLES-2024-1086", "KH-ESC-DIRTYCOW-2016-5195":
			rules[i].Fn = perNodeVersionRule(rules[i].Fn)
		}
	}
	return rules
}

func perNodeVersionRule(fn scanner.RuleFn) scanner.RuleFn {
	return func(inv *scanner.Inventory, sess *kubectx.Session) []scanner.Finding {
		if len(inv.Nodes) == 0 {
			return fn(inv, sess)
		}
		var out []scanner.Finding
		for _, node := range inv.Nodes {
			scoped := *inv
			scoped.Nodes = []corev1.Node{node}
			scoped.Pods = nil
			for _, pod := range inv.Pods {
				if pod.Spec.NodeName == node.Name {
					scoped.Pods = append(scoped.Pods, pod)
				}
			}
			for _, finding := range fn(&scoped, sess) {
				if finding.Resource.Kind == "Cluster" {
					finding.Resource = scanner.Resource{Kind: "Node", Name: node.Name, UID: string(node.UID)}
				}
				finding.Evidence = "node=" + node.Name + " " + strings.ReplaceAll(finding.Evidence, "Node[0]", "node/"+node.Name)
				finding.Tags = append(finding.Tags, "version-unverified")
				finding.Description += " Version banners are a heuristic; distribution backports and the actual vulnerable binary require verification. No exploit was executed."
				out = append(out, finding)
			}
		}
		return out
	}
}

func hostPathLike(p corev1.Pod, container corev1.Container, targets ...string) (string, bool) {
	for _, mount := range container.VolumeMounts {
		if mount.ReadOnly || mount.SubPathExpr != "" {
			continue
		}
		for _, volume := range p.Spec.Volumes {
			if volume.Name != mount.Name || volume.HostPath == nil {
				continue
			}
			hp := path.Clean(path.Join(volume.HostPath.Path, mount.SubPath))
			for _, target := range targets {
				target = path.Clean(target)
				if hp == "/" || hp == target || strings.HasPrefix(target, hp+"/") {
					return hp, true
				}
			}
		}
	}
	return "", false
}

func containerHasCap(p corev1.Pod, capName string) (string, bool) {
	for _, c := range allContainers(p) {
		if hasContainerCap(c, capName) {
			return c.Name, true
		}
	}
	return "", false
}

func hasContainerCap(container corev1.Container, name string) bool {
	sc := container.SecurityContext
	if sc == nil {
		return false
	}
	if sc.Privileged != nil && *sc.Privileged {
		return true
	}
	if sc.Capabilities != nil {
		for _, capability := range sc.Capabilities.Add {
			if strings.EqualFold(string(capability), name) || capability == "ALL" {
				return true
			}
		}
	}
	return false
}

func podRunsAsRoot(p corev1.Pod) bool {
	for _, c := range allContainers(p) {
		if scanner.ContainerRunsAsRoot(&p, c) {
			return true
		}
	}
	return false
}

func runtimeBanner(inv *scanner.Inventory) (name, ver string) {
	if len(inv.Nodes) == 0 {
		return "", ""
	}
	cr := inv.Nodes[0].Status.NodeInfo.ContainerRuntimeVersion
	parts := strings.SplitN(cr, "://", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return cr, ""
}

func kernelVer(inv *scanner.Inventory) string {
	freq := map[string]int{}
	for _, n := range inv.Nodes {
		freq[n.Status.NodeInfo.KernelVersion]++
	}
	best := ""
	bestN := 0
	for k, n := range freq {
		if n > bestN {
			best, bestN = k, n
		}
	}
	return best
}

func versionTuple(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+~"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {

		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func versionLT(v, ref string) bool {
	a := versionTuple(v)
	b := versionTuple(ref)
	for i := 0; i < len(b); i++ {
		var ai int
		if i < len(a) {
			ai = a[i]
		}
		if ai < b[i] {
			return true
		}
		if ai > b[i] {
			return false
		}
	}
	return false
}

var _ = regexp.MustCompile

func ruleRuncLeakyVesselsCWD(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	rt, ver := runtimeBanner(inv)
	if !strings.HasPrefix(strings.ToLower(rt), "containerd") &&
		!strings.HasPrefix(strings.ToLower(rt), "docker") &&
		!strings.HasPrefix(strings.ToLower(rt), "cri-o") {
		return nil
	}

	type fix struct {
		runtime string
		min     string
	}
	patched := []fix{
		{"containerd", "1.7.13"}, {"docker", "25.0.2"}, {"cri-o", "1.28.4"},
	}
	vulnerable := true
	for _, f := range patched {
		if strings.HasPrefix(strings.ToLower(rt), f.runtime) && !versionLT(ver, f.min) {
			vulnerable = false
		}
	}
	if !vulnerable {
		return nil
	}
	out := []scanner.Finding{{
		Severity:       scanner.SevCritical,
		Title:          "runc CVE-2024-21626 — vulnerable container runtime detected (Leaky Vessels)",
		Description:    fmt.Sprintf("Cluster nodes run %s %s which is BEFORE the patched runc version. CVE-2024-21626 (\"Leaky Vessels\") lets a malicious image reuse a leaked file descriptor on the host to execute arbitrary code outside the container. Any user able to run `kubectl exec` into ANY workload can exploit this.", rt, ver),
		Resource:       scanner.Resource{Kind: "Cluster", Name: rt + "/" + ver},
		Evidence:       fmt.Sprintf("Node[0].containerRuntimeVersion=%s://%s", rt, ver),
		Impact:         "Full host compromise from inside any container; equivalent to root on the node. CISA KEV-eligible.",
		Recommendation: "Upgrade runc to ≥1.1.12 (which means containerd ≥1.7.13 / Docker ≥25.0.2 / CRI-O ≥1.28.4). Verify with `runc --version` on each node.",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
			"https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/",
			"https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv",
		},
		MitreATTACK: []string{"T1611"},
		Tags:        []string{"container-escape", "runc", "leaky-vessels", "cve-2024-21626"},
	}}
	return out
}

func ruleBuildKitCacheRace(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	if !workloadDoesImageBuilds(inv) {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevHigh,
		Title:          "BuildKit cache mount race (CVE-2024-23651) — image-building workload detected",
		Description:    "An image-building workload (BuildKit, kaniko, buildah, img) was detected. Versions of BuildKit before 0.12.5 contain a race condition (CVE-2024-23651) that lets a crafted Dockerfile read or write arbitrary host paths during cache-mount setup.",
		Resource:       scanner.Resource{Kind: "Cluster", Name: "buildkit-workloads"},
		Evidence:       "Found one or more pods running buildkit / kaniko / buildah / img.",
		Impact:         "Build-time host filesystem read/write — attacker who can submit a Dockerfile can read /etc/shadow or write a backdoor to the build node.",
		Recommendation: "Upgrade BuildKit to ≥ 0.12.5. Where possible, run image builds in an isolated namespace with strict admission policies.",
		References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-23651", "https://github.com/moby/buildkit/security/advisories/GHSA-m3r6-h7wv-7xxv"},
		MitreATTACK:    []string{"T1611"},
		Tags:           []string{"container-escape", "buildkit", "leaky-vessels", "cve-2024-23651"},
	}}
}

func ruleBuildKitHostTraversal(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	if !workloadDoesImageBuilds(inv) {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevHigh,
		Title:          "BuildKit host path traversal (CVE-2024-23652)",
		Description:    "BuildKit < 0.12.5 mishandles symlinks during `RUN --mount` causing host path traversal. Detected because an image-building workload is present in this cluster.",
		Resource:       scanner.Resource{Kind: "Cluster", Name: "buildkit-workloads"},
		Impact:         "Write-anywhere on the build node — escape from buildkitd to the worker host.",
		Recommendation: "Upgrade BuildKit to ≥ 0.12.5.",
		References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-23652"},
		MitreATTACK:    []string{"T1611"},
		Tags:           []string{"container-escape", "buildkit", "leaky-vessels", "cve-2024-23652"},
	}}
}

func ruleBuildKitPrivileged(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	if !workloadDoesImageBuilds(inv) {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevHigh,
		Title:          "BuildKit privileged-by-default (CVE-2024-23653)",
		Description:    "BuildKit < 0.12.5 lets a malicious frontend gain privileged execution on the host. Detected because an image-building workload is present.",
		Resource:       scanner.Resource{Kind: "Cluster", Name: "buildkit-workloads"},
		Impact:         "Privileged host code execution — full node compromise.",
		Recommendation: "Upgrade BuildKit to ≥ 0.12.5.",
		References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-23653"},
		MitreATTACK:    []string{"T1611"},
		Tags:           []string{"container-escape", "buildkit", "leaky-vessels", "cve-2024-23653"},
	}}
}

func ruleRunc2025_31133(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return runcVersionAdvisory(inv,
		"KH-ESC-RUNC-2025-31133",
		"runc CVE-2025-31133 — bind-mount in /proc enables arbitrary host write",
		"runc 1.2.4", "runc 1.1.16",
		"https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm",
		"CVE-2025-31133")
}
func ruleRunc2025_52565(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return runcVersionAdvisory(inv,
		"KH-ESC-RUNC-2025-52565",
		"runc CVE-2025-52565 — procfs override during init",
		"runc 1.2.4", "runc 1.1.16",
		"https://github.com/opencontainers/runc/security/advisories/GHSA-9493-hgw9-w5pq",
		"CVE-2025-52565")
}
func ruleRunc2025_52881(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	return runcVersionAdvisory(inv,
		"KH-ESC-RUNC-2025-52881",
		"runc CVE-2025-52881 — DoS via gadget primitive (preludes RCE chains)",
		"runc 1.2.4", "runc 1.1.16",
		"https://github.com/opencontainers/runc/security/advisories/GHSA-vfwm-x577-jwrc",
		"CVE-2025-52881")
}

func ruleRunc2019_5736(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	rt, ver := runtimeBanner(inv)
	if rt == "" {
		return nil
	}

	tooOld := false
	switch strings.ToLower(rt) {
	case "containerd":
		tooOld = versionLT(ver, "1.2.4")
	case "docker":
		tooOld = versionLT(ver, "18.09.2")
	case "cri-o":
		tooOld = versionLT(ver, "1.0.0")
	}
	if !tooOld {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevCritical,
		Title:          "runc CVE-2019-5736 — host runc binary overwrite",
		Description:    fmt.Sprintf("Container runtime %s/%s is before the runc 1.0.0-rc6 patch. CVE-2019-5736 lets a process inside a container overwrite the host runc binary by abusing /proc/self/exe.", rt, ver),
		Resource:       scanner.Resource{Kind: "Cluster", Name: rt + "/" + ver},
		Evidence:       fmt.Sprintf("Node[0].containerRuntimeVersion=%s://%s", rt, ver),
		Impact:         "Once exploited, every subsequent `docker exec` / kubelet exec into ANY container runs the attacker's payload as root on the node.",
		Recommendation: "Upgrade the container runtime — see release notes for runc 1.0.0-rc6 backports.",
		References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-5736"},
		MitreATTACK:    []string{"T1611"},
		Tags:           []string{"container-escape", "runc", "cve-2019-5736"},
	}}
}

func ruleContainerd2022_23648(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	rt, ver := runtimeBanner(inv)
	if !strings.HasPrefix(strings.ToLower(rt), "containerd") {
		return nil
	}

	t := versionTuple(ver)
	if len(t) < 3 {
		return nil
	}
	vuln := false
	switch {
	case t[0] == 1 && t[1] == 4 && t[2] < 13:
		vuln = true
	case t[0] == 1 && t[1] == 5 && t[2] < 10:
		vuln = true
	case t[0] == 1 && t[1] == 6 && t[2] < 1:
		vuln = true
	case t[0] == 1 && t[1] < 4:
		vuln = true
	case t[0] == 0:
		vuln = true
	}
	if !vuln {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevHigh,
		Title:          "containerd CVE-2022-23648 — image config rootfs path traversal",
		Description:    fmt.Sprintf("containerd %s is vulnerable to CVE-2022-23648. A specially crafted image causes containerd to mount a host path as a read-only volume inside the container — leaking host files (e.g. /etc/shadow).", ver),
		Resource:       scanner.Resource{Kind: "Cluster", Name: "containerd/" + ver},
		Evidence:       "Node[0].containerRuntimeVersion=containerd://" + ver,
		Impact:         "Read-only access to arbitrary host files from inside any pod that pulls a malicious image.",
		Recommendation: "Upgrade containerd to ≥1.6.1, ≥1.5.10, or ≥1.4.13 depending on the LTS line.",
		References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-23648"},
		MitreATTACK:    []string{"T1611"},
		Tags:           []string{"container-escape", "containerd", "cve-2022-23648"},
	}}
}

func ruleCgroupReleaseAgent(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, container := range allContainers(p) {
			if !hasContainerCap(container, "SYS_ADMIN") || !scanner.ContainerRunsAsRoot(&p, container) {
				continue
			}
			name := container.Name
			out = append(out, scanner.Finding{
				Severity:       scanner.SevCritical,
				Title:          "Root container with SYS_ADMIN exposes a potential cgroup escape",
				Description:    fmt.Sprintf("Pod %s/%s container %s has CAP_SYS_ADMIN and runs as root. CVE-2022-0492 abuses unprivileged cgroup v1 mounts: a process can write its own user-mode-helper into the release_agent file and trigger it as root on the host.", p.Namespace, p.Name, name),
				Resource:       scanner.Resource{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
				Evidence:       fmt.Sprintf("CAP_SYS_ADMIN added on %s and pod runs as UID 0.", name),
				Impact:         "Potential host execution if writable cgroup v1 and the required kernel/runtime conditions are present. Cgroup mode and exploitability are unverified.",
				Recommendation: "Drop CAP_SYS_ADMIN; add seccomp/AppArmor policies; ensure CRI runs cgroup v2 unified hierarchy where release_agent is gone.",
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2022-0492",
					"https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/",
				},
				MitreATTACK: []string{"T1611"},
				Tags:        []string{"container-escape", "cgroup", "cve-2022-0492"},
			})
		}
	}
	return out
}

func ruleFsConfig2022_0185(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	kv := kernelVer(inv)
	if kv == "" {
		return nil
	}

	if !versionLT(kv, "5.16.2") {
		return nil
	}

	var out []scanner.Finding
	for _, p := range inv.Pods {
		_, hasAdmin := containerHasCap(p, "SYS_ADMIN")
		if !hasAdmin && !podRunsAsRoot(p) {
			continue
		}
		ev := "kernel=" + kv
		if hasAdmin {
			ev += " + CAP_SYS_ADMIN"
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevHigh,
			Title:          "Vulnerable kernel + privileged pod = CVE-2022-0185 escape vector",
			Description:    fmt.Sprintf("Pod %s/%s runs on kernel %s which predates the CVE-2022-0185 fix. Combined with CAP_SYS_ADMIN or root, the fsconfig() heap overflow is reachable, leading to host root.", p.Namespace, p.Name, kv),
			Resource:       scanner.Resource{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
			Evidence:       ev,
			Impact:         "Full container escape and root on the node.",
			Recommendation: "Upgrade node kernel to ≥5.16.2 (or your distro's backport). Drop CAP_SYS_ADMIN and unprivilege user namespaces (sysctl user.max_user_namespaces=0).",
			References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-0185", "https://www.crowdstrike.com/en-us/blog/cve-2022-0185-kubernetes-container-escape/"},
			MitreATTACK:    []string{"T1611"},
			Tags:           []string{"container-escape", "kernel", "cve-2022-0185"},
		})
	}
	return out
}

func ruleDirtyPipe2022_0847(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	kv := kernelVer(inv)
	if kv == "" {
		return nil
	}
	t := versionTuple(kv)
	if len(t) < 2 {
		return nil
	}

	if t[0] < 5 || (t[0] == 5 && t[1] < 8) {
		return nil
	}

	patched := false
	switch {
	case t[0] >= 6:
		patched = true
	case t[0] == 5 && t[1] == 16 && len(t) >= 3 && t[2] >= 11:
		patched = true
	case t[0] == 5 && t[1] == 15 && len(t) >= 3 && t[2] >= 25:
		patched = true
	case t[0] == 5 && t[1] == 10 && len(t) >= 3 && t[2] >= 102:
		patched = true
	case t[0] == 5 && t[1] > 16:
		patched = true
	}
	if patched {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevHigh,
		Title:          "Kernel CVE-2022-0847 (Dirty Pipe) on at least one node",
		Description:    fmt.Sprintf("Node kernel %s is in the Dirty Pipe vulnerable range (5.8 ≤ kernel < 5.10.102 / 5.15.25 / 5.16.11). Any unprivileged process can overwrite arbitrary read-only files, including SUID binaries, leading to root.", kv),
		Resource:       scanner.Resource{Kind: "Node", Name: "kernel/" + kv},
		Evidence:       "kernelVersion=" + kv,
		Impact:         "Local privilege escalation inside any container; combined with SUID host binaries this is a host-root primitive.",
		Recommendation: "Upgrade kernel to a fixed version. Apply seccomp profile that blocks `pipe2` exotic flags as a stop-gap.",
		References:     []string{"https://dirtypipe.cm4all.com/", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"},
		MitreATTACK:    []string{"T1068"},
		Tags:           []string{"container-escape", "kernel", "dirty-pipe", "cve-2022-0847"},
	}}
}

func ruleNftables2024_1086(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	kv := kernelVer(inv)
	if kv == "" {
		return nil
	}
	t := versionTuple(kv)
	if len(t) < 2 {
		return nil
	}

	inRange := false
	switch {
	case t[0] == 5 && t[1] >= 14:
		inRange = true
	case t[0] == 6 && t[1] <= 6:
		inRange = true
	}
	if !inRange {
		return nil
	}

	if t[0] == 6 && (t[1] == 6 && len(t) >= 3 && t[2] >= 15 || t[1] == 7 && len(t) >= 3 && t[2] >= 3 || t[1] >= 8) {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevHigh,
		Title:          "Kernel CVE-2024-1086 (nf_tables UAF) on at least one node",
		Description:    fmt.Sprintf("Node kernel %s is in the CVE-2024-1086 vulnerable range. Public PoCs achieve root in any container that can use the nft_chain feature (default on most distros).", kv),
		Resource:       scanner.Resource{Kind: "Node", Name: "kernel/" + kv},
		Evidence:       "kernelVersion=" + kv,
		Impact:         "Local privilege escalation to host root; trivially turns a single pod compromise into a node compromise.",
		Recommendation: "Upgrade kernel to ≥6.6.15 / 6.7.3 (or your distro's backport). Apply seccomp profile that blocks setsockopt(IP_SET_OP_RANGE) etc. for unprivileged users.",
		References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-1086", "https://github.com/Notselwyn/CVE-2024-1086"},
		MitreATTACK:    []string{"T1068"},
		Tags:           []string{"container-escape", "kernel", "cve-2024-1086"},
	}}
}

func ruleDirtyCow2016_5195(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	kv := kernelVer(inv)
	if kv == "" || !versionLT(kv, "4.8.3") {
		return nil
	}
	return []scanner.Finding{{
		Severity:       scanner.SevCritical,
		Title:          "Legacy kernel — Dirty COW (CVE-2016-5195)",
		Description:    fmt.Sprintf("Node kernel %s is older than 4.8.3 and vulnerable to Dirty COW.", kv),
		Resource:       scanner.Resource{Kind: "Node", Name: "kernel/" + kv},
		Evidence:       "kernelVersion=" + kv,
		Impact:         "Trivial local privilege escalation. Any container = host root.",
		Recommendation: "Replace the node — its kernel is end-of-life.",
		References:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-5195"},
		MitreATTACK:    []string{"T1068"},
		Tags:           []string{"container-escape", "kernel", "dirty-cow", "cve-2016-5195"},
	}}
}

func ruleCorePattern(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, container := range allContainers(p) {
			if !hasContainerCap(container, "SYS_ADMIN") || !scanner.ContainerRunsAsRoot(&p, container) {
				continue
			}
			hostPath, ok := hostPathLike(p, container, "/proc/sys/kernel/core_pattern")
			if !ok {
				continue
			}
			cap := container.Name
			out = append(out, scanner.Finding{
				Severity:       scanner.SevCritical,
				Title:          "/proc mount + CAP_SYS_ADMIN = core_pattern host RCE",
				Description:    fmt.Sprintf("Pod %s/%s has a root container %s with CAP_SYS_ADMIN and a writable host mount %s containing core_pattern. This is a host-execution precondition, not a demonstrated exploit.", p.Namespace, p.Name, cap, hostPath),
				Resource:       scanner.Resource{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
				Evidence:       fmt.Sprintf("hostPath=%s writable + CAP_SYS_ADMIN(%s)", hostPath, cap),
				Impact:         "Direct host RCE without exploiting any CVE — pure misconfig.",
				Recommendation: "Do not mount /proc from the host; if absolutely required, mount read-only and drop CAP_SYS_ADMIN.",
				References:     []string{"https://book.hacktricks.xyz/linux-hardening/privilege-escalation/escaping-from-jails/escaping-from-jail-via-core_pattern"},
				MitreATTACK:    []string{"T1611"},
				Tags:           []string{"container-escape", "core_pattern", "misconfig"},
			})
		}
	}
	return out
}

func ruleProcSelfExe(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	dangerous := []string{
		"/usr/sbin/runc", "/usr/bin/runc", "/usr/local/sbin/runc",
		"/usr/bin/docker", "/usr/bin/containerd", "/var/run/docker.sock",
		"/run/containerd/containerd.sock",
	}
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			hp := v.HostPath.Path
			for _, d := range dangerous {
				if strings.HasPrefix(hp, d) || hp == d {
					out = append(out, scanner.Finding{
						Severity:       scanner.SevCritical,
						Title:          "Container mounts the host container-runtime binary or socket",
						Description:    fmt.Sprintf("Pod %s/%s mounts host path %s. This is a single command away from container escape (`docker exec`, `runc exec`, `crictl exec` or simply spawning a sibling container as root).", p.Namespace, p.Name, hp),
						Resource:       scanner.Resource{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
						Evidence:       "hostPath=" + hp,
						Impact:         "One-line container escape, no CVE required.",
						Recommendation: "Remove the mount. If you really need cluster-internal docker socket access, use a sidecar bridge with a socket-proxy that whitelists the API methods.",
						References:     []string{"https://github.com/cyberark/kubeletmein"},
						MitreATTACK:    []string{"T1611"},
						Tags:           []string{"container-escape", "runtime-socket", "misconfig"},
					})
					break
				}
			}
		}
	}
	return out
}

func rulePtraceCrossNS(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		share := p.Spec.ShareProcessNamespace != nil && *p.Spec.ShareProcessNamespace
		hostPID := p.Spec.HostPID
		if !share && !hostPID {
			continue
		}
		if name, ok := containerHasCap(p, "SYS_PTRACE"); ok {
			sev := scanner.SevHigh
			if hostPID {
				sev = scanner.SevCritical
			}
			out = append(out, scanner.Finding{
				Severity:       sev,
				Title:          "SYS_PTRACE + shared/host PID namespace = process injection escape",
				Description:    fmt.Sprintf("Pod %s/%s container %s has CAP_SYS_PTRACE; the pod has hostPID=%v shareProcessNamespace=%v. Combined, an attacker can ptrace into either sidecar containers (steal tokens) or host processes (kubelet, kernel daemons → host root).", p.Namespace, p.Name, name, hostPID, share),
				Resource:       scanner.Resource{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
				Evidence:       fmt.Sprintf("CAP_SYS_PTRACE(%s) hostPID=%v shareProcessNamespace=%v", name, hostPID, share),
				Impact:         "Sidecar token theft or full host compromise depending on the namespace flag.",
				Recommendation: "Drop CAP_SYS_PTRACE. Avoid hostPID. If shareProcessNamespace is required for a debugging sidecar, gate it behind admission policy.",
				References:     []string{"https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/"},
				MitreATTACK:    []string{"T1611", "T1055.008"},
				Tags:           []string{"container-escape", "ptrace", "namespace"},
			})
		}
	}
	return out
}

func ruleDangerousDevCaps(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	wanted := []string{"SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH", "MKNOD"}
	for _, p := range inv.Pods {
		var hits []string
		for _, w := range wanted {
			if name, ok := containerHasCap(p, w); ok {
				hits = append(hits, w+"("+name+")")
			}
		}
		if len(hits) == 0 {
			continue
		}
		sev := scanner.SevHigh

		for _, h := range hits {
			if strings.HasPrefix(h, "SYS_MODULE") {
				sev = scanner.SevCritical
			}
		}
		out = append(out, scanner.Finding{
			Severity:       sev,
			Title:          "Pod has capabilities equivalent to root on the host",
			Description:    fmt.Sprintf("Pod %s/%s adds capability(ies) %s. SYS_MODULE = load any kernel module → instant host root. SYS_RAWIO = direct port I/O. DAC_READ_SEARCH = read every host file. MKNOD = create device nodes (paired with hostPath = host disk read/write).", p.Namespace, p.Name, strings.Join(hits, ",")),
			Resource:       scanner.Resource{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
			Evidence:       "added caps: " + strings.Join(hits, ", "),
			Impact:         "Container escape with a 1-2 line PoC for each capability.",
			Recommendation: "Drop the capability. Use a tightly-scoped `securityContext.capabilities.add` that contains only what the workload genuinely needs.",
			References:     []string{"https://man7.org/linux/man-pages/man7/capabilities.7.html"},
			MitreATTACK:    []string{"T1611"},
			Tags:           []string{"container-escape", "capabilities"},
		})
	}
	return out
}

func ruleCgroupMount(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {

		var matchedVol string
		for _, v := range p.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			if strings.HasPrefix(v.HostPath.Path, "/sys/fs/cgroup") {
				matchedVol = v.Name
				break
			}
		}
		if matchedVol == "" {
			continue
		}

		for _, c := range allContainers(p) {
			for _, m := range c.VolumeMounts {
				if m.Name != matchedVol {
					continue
				}
				if m.ReadOnly {
					continue
				}
				if c.SecurityContext == nil {
					continue
				}
				priv := c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged
				if !priv {
					continue
				}
				out = append(out, scanner.Finding{
					Severity:       scanner.SevCritical,
					Title:          "Privileged container with writable /sys/fs/cgroup → release_agent escape",
					Description:    fmt.Sprintf("Pod %s/%s container %s mounts host /sys/fs/cgroup writable AND runs privileged. Classic exploit: write a notify_on_release script, trigger cgroup teardown, the kernel runs the script as root on the host.", p.Namespace, p.Name, c.Name),
					Resource:       scanner.Resource{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
					Evidence:       "hostPath=/sys/fs/cgroup readOnly=false privileged=true",
					Impact:         "Single-step container escape. No CVE required.",
					Recommendation: "Mount cgroup read-only OR drop privileged + CAP_SYS_ADMIN.",
					References:     []string{"https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/"},
					MitreATTACK:    []string{"T1611"},
					Tags:           []string{"container-escape", "cgroup", "release_agent"},
				})
			}
		}
	}
	return out
}

func ruleDevMem(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, v := range p.Spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			hp := v.HostPath.Path
			if hp == "/dev" || strings.HasPrefix(hp, "/dev/mem") || strings.HasPrefix(hp, "/dev/kmem") || strings.HasPrefix(hp, "/dev/port") {
				out = append(out, scanner.Finding{
					Severity:       scanner.SevCritical,
					Title:          "Container mounts host /dev/mem / /dev/kmem / /dev/port",
					Description:    fmt.Sprintf("Pod %s/%s mounts host %s. Direct read/write of physical memory leads to immediate kernel compromise.", p.Namespace, p.Name, hp),
					Resource:       scanner.Resource{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
					Evidence:       "hostPath=" + hp,
					Impact:         "Kernel-level container escape, ring-0 access.",
					Recommendation: "Remove this mount. There is almost never a legitimate reason for a workload to need raw kernel memory access.",
					References:     []string{"https://man7.org/linux/man-pages/man4/mem.4.html"},
					MitreATTACK:    []string{"T1611"},
					Tags:           []string{"container-escape", "devfs", "kernel"},
				})
			}
		}
	}
	return out
}

func ruleEscapePosture(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	rt, ver := runtimeBanner(inv)
	kv := kernelVer(inv)
	return []scanner.Finding{{
		Severity:       scanner.SevInfo,
		Title:          "Container escape posture — rule pack executed",
		Description:    fmt.Sprintf("Container-escape rule pack (KH-ESC-*) evaluated. Detected runtime=%s/%s kernel=%s. Refer to the EscapePosture field in scan metadata for the aggregated verdict (no-known-escape / vulnerable / exploited).", rt, ver, kv),
		Resource:       scanner.Resource{Kind: "Cluster", Name: "escape-posture"},
		Evidence:       fmt.Sprintf("runtime=%s/%s kernel=%s nodes=%d pods=%d", rt, ver, kv, len(inv.Nodes), len(inv.Pods)),
		Recommendation: "Examine every other KH-ESC-* finding to confirm whether known escape techniques are mitigated.",
		Tags:           []string{"container-escape", "posture"},
	}}
}

func workloadDoesImageBuilds(inv *scanner.Inventory) bool {
	needles := []string{"buildkit", "kaniko", "buildah", "/img:", "makisu", "jib"}
	for _, p := range inv.Pods {
		for _, c := range p.Spec.Containers {
			img := strings.ToLower(c.Image)
			for _, n := range needles {
				if strings.Contains(img, n) {
					return true
				}
			}
		}
		if strings.Contains(strings.ToLower(p.Spec.ServiceAccountName), "build") {
			return true
		}
	}
	return false
}

func runcVersionAdvisory(inv *scanner.Inventory, ruleID, title, fix12, fix11, ref, cve string) []scanner.Finding {
	rt, ver := runtimeBanner(inv)
	if rt == "" {
		return nil
	}

	tooOld := false
	switch strings.ToLower(rt) {
	case "containerd":
		tooOld = versionLT(ver, "1.7.27")
	case "docker":
		tooOld = versionLT(ver, "27.4.0")
	case "cri-o":
		tooOld = versionLT(ver, "1.31.4")
	}
	if !tooOld {
		return nil
	}
	return []scanner.Finding{{
		RuleID:         ruleID,
		Category:       scanner.CatEscape,
		Severity:       scanner.SevHigh,
		Title:          title,
		Description:    fmt.Sprintf("Container runtime %s/%s is older than the fix line that includes %s. The runc Nov-2025 trio (CVE-2025-31133 / 52565 / 52881) gives a malicious image arbitrary host write primitives.", rt, ver, cve),
		Resource:       scanner.Resource{Kind: "Cluster", Name: rt + "/" + ver},
		Evidence:       fmt.Sprintf("Node[0].containerRuntimeVersion=%s://%s", rt, ver),
		Impact:         "Container escape: arbitrary write of host files; combined with runc 1.1.x's `process.cwd` semantics it leads to RCE on the node.",
		Recommendation: fmt.Sprintf("Upgrade to runc ≥ %s (1.2.x line) or ≥ %s (1.1.x LTS line). For your runtime: containerd ≥ 1.7.27, Docker ≥ 27.4.0, CRI-O ≥ 1.31.4.", fix12, fix11),
		References:     []string{ref, "https://nvd.nist.gov/vuln/detail/" + cve},
		MitreATTACK:    []string{"T1611"},
		Tags:           []string{"container-escape", "runc", strings.ToLower(cve)},
	}}
}
