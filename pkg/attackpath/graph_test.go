package attackpath

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func reachable(g *Graph, start, target string) bool {
	for _, path := range FindFrom(g, []string{start}, 8) {
		if path.Nodes[len(path.Nodes)-1].ID == target {
			return true
		}
	}
	return false
}

func TestEphemeralInjectionIsNotExecAndNamedPotentialPathsRetainTheirStatus(t *testing.T) {
	inv := &scanner.Inventory{
		Pods: []corev1.Pod{privilegedPod("target")},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "tenant-a"},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/ephemeralcontainers"},
				Verbs: []string{"update"}, ResourceNames: []string{"target"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "debug"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		}},
	}
	g := Build(inv)
	for _, edge := range g.Out["Role/tenant-a/debug"] {
		if edge.Kind == EdgeGrantsExec {
			t.Fatal("ephemeral mutation permission became pods/exec")
		}
	}
	AugmentEphemeralContainers(g, "User/alice", []scanner.EphemeralAssessment{{
		Namespace: "tenant-a", PodName: "target", Running: true, NodeName: "worker-1", NodeRole: "unknown",
		HostConditions: "hostPID requires admitted root privileged debug profile",
		Permissions:    map[string]scanner.EphemeralPermission{"update pods/ephemeralcontainers": {Allowed: true}},
	}})
	paths := FindFrom(g, []string{"User/alice"}, 6)
	snapshot := Snapshot(g, paths, "User/alice")
	found := false
	for _, node := range snapshot.Nodes {
		if node.Kind == "EphemeralCandidate" {
			found = true
			if node.Status != "potential" {
				t.Fatal("potential candidate lost status")
			}
		}
	}
	if !found {
		t.Fatal("named ephemeral candidate was not included in the attack paths")
	}
	for _, edge := range snapshot.Edges {
		if strings.Contains(edge.To, "EphemeralCandidate/") && edge.Status != "potential" {
			t.Fatal("candidate edge lost its unverified status")
		}
	}
}

func privilegedPod(name string) corev1.Pod {
	root, privileged, automount := int64(0), true, false
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-a"},
		Spec: corev1.PodSpec{
			NodeName: "worker-1", HostPID: true, ServiceAccountName: "runner",
			AutomountServiceAccountToken: &automount,
			Containers: []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{
				Privileged: &privileged, RunAsUser: &root,
			}}},
		},
	}
}

func TestScopedClusterRoleDoesNotGrantClusterAdmin(t *testing.T) {
	inv := &scanner.Inventory{
		ClusterRoles: []rbacv1.ClusterRole{{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "local-admin", Namespace: "tenant-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		}},
	}
	g := Build(inv)
	if reachable(g, "User/alice", "ClusterAdmin/*") {
		t.Fatal("RoleBinding became full-cluster authority")
	}
	if len(FindFrom(g, []string{"User/alice"}, 6)) == 0 {
		t.Fatal("namespace-admin pod creation capability disappeared in an empty namespace")
	}
	inv.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "global-admin"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob"}},
	}}
	g = Build(inv)
	if !reachable(g, "User/bob", "ClusterAdmin/*") || reachable(g, "User/alice", "ClusterAdmin/*") {
		t.Fatal("global and namespace-scoped role grants were conflated")
	}
}

func legacyTokenGraphFixture() *scanner.Inventory {
	disabled := false
	return &scanner.Inventory{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team"},
			Spec: corev1.PodSpec{ServiceAccountName: "admin", AutomountServiceAccountToken: &disabled,
				Containers: []corev1.Container{{Name: "app"}},
			},
		}},
		Secrets: []corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-token", Namespace: "team",
				Annotations: map[string]string{"kubernetes.io/service-account.name": "guest"}},
			Type: corev1.SecretTypeServiceAccountToken, Data: map[string][]byte{"token": []byte("synthetic-token")},
		}},
		ClusterRoles: []rbacv1.ClusterRole{{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "team", Name: "admin"}},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "exec", Namespace: "team"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "exec"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		}},
	}
}

func TestMountedLegacyTokenUsesItsActualOwner(t *testing.T) {
	inv := legacyTokenGraphFixture()
	inv.Pods[0].Spec.Volumes = []corev1.Volume{{
		Name: "credentials", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "legacy-token"}},
	}}
	inv.Pods[0].Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "credentials", MountPath: "/credentials"}}
	graph := Build(inv)
	if reachable(graph, "User/alice", "ClusterAdmin/*") {
		t.Fatal("guest token fabricated credentials for the pod's admin SA")
	}
	foundOwner := false
	for _, edge := range graph.Out["Secret/team/legacy-token"] {
		foundOwner = foundOwner || edge.To == "ServiceAccount/team/guest"
	}
	if !foundOwner {
		t.Fatal("foreign legacy token lost its actual owner")
	}
}

func TestSelectedSecretKeysDoNotExposeLegacyToken(t *testing.T) {
	for _, mode := range []string{"env", "items", "subpath", "projected"} {
		t.Run(mode, func(t *testing.T) {
			inv := legacyTokenGraphFixture()
			inv.Secrets[0].Annotations["kubernetes.io/service-account.name"] = "admin"
			container := &inv.Pods[0].Spec.Containers[0]
			switch mode {
			case "env":
				container.Env = []corev1.EnvVar{{
					Name: "CA", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "legacy-token"}, Key: "ca.crt",
					}},
				}}
			case "projected":
				inv.Pods[0].Spec.Volumes = []corev1.Volume{{
					Name: "credentials", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
						Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: "legacy-token"},
							Items:                []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}},
						}}},
					}},
				}}
				container.VolumeMounts = []corev1.VolumeMount{{Name: "credentials", MountPath: "/credentials"}}
			default:
				volume := corev1.Volume{
					Name: "credentials", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "legacy-token"}},
				}
				mount := corev1.VolumeMount{Name: "credentials", MountPath: "/credentials"}
				if mode == "items" {
					volume.Secret.Items = []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}
				} else {
					mount.SubPath = "ca.crt"
				}
				inv.Pods[0].Spec.Volumes = []corev1.Volume{volume}
				container.VolumeMounts = []corev1.VolumeMount{mount}
			}
			if reachable(Build(inv), "User/alice", "ClusterAdmin/*") {
				t.Fatal("ca.crt exposure became an administrator's token")
			}
		})
	}
}

func TestNamedSecretListAndWatchRemainTraversable(t *testing.T) {
	for _, verb := range []string{"list", "watch"} {
		inv := legacyTokenGraphFixture()
		inv.Secrets[0].Annotations["kubernetes.io/service-account.name"] = "admin"
		inv.Roles[0].Rules = []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{verb}, ResourceNames: []string{"legacy-token"},
		}}
		if !reachable(Build(inv), "User/alice", "ClusterAdmin/*") {
			t.Fatalf("name-restricted %s with metadata.name selector was missed", verb)
		}
	}
}

func TestNamedPodExecReachesEscapeAndRespectsScope(t *testing.T) {
	inv := &scanner.Inventory{
		Pods: []corev1.Pod{privilegedPod("target"), privilegedPod("other")},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "exec-one", Namespace: "tenant-a"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}, ResourceNames: []string{"target"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "exec-one", Namespace: "tenant-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "exec-one"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		}},
	}
	g := Build(inv)
	if !reachable(g, "User/alice", "Node/worker-1") {
		t.Fatal("named pods/exec did not connect to the real escaping pod")
	}
	role := "Role/tenant-a/exec-one"
	for _, edge := range g.Out[role] {
		if edge.Kind == EdgeGrantsExec && edge.To != "Pod/tenant-a/target" {
			t.Fatalf("named exec reached another pod: %+v", edge)
		}
	}
	inv.Roles[0].Rules[0].APIGroups = []string{"custom.example"}
	if reachable(Build(inv), "User/alice", "Node/worker-1") {
		t.Fatal("custom API-group permission authorized core pod exec")
	}
}

func TestServiceAccountUsageIsNotPodExecution(t *testing.T) {
	inv := &scanner.Inventory{Pods: []corev1.Pod{privilegedPod("target")}}
	g := Build(inv)
	if reachable(g, "ServiceAccount/tenant-a/runner", "Node/worker-1") {
		t.Fatal("structural SA usage became pod execution")
	}
}

func TestSecretReadAndTokenRequestReachNamedAdminSA(t *testing.T) {
	inv := &scanner.Inventory{
		ServiceAccounts: []corev1.ServiceAccount{
			{ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: "tenant-a"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "tenant-a"}},
		},
		Secrets: []corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{Name: "victim-token", Namespace: "tenant-a",
				Annotations: map[string]string{"kubernetes.io/service-account.name": "victim"}},
			Type: corev1.SecretTypeServiceAccountToken, Data: map[string][]byte{"token": []byte("synthetic-test-token")},
		}},
		ClusterRoles: []rbacv1.ClusterRole{{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "victim", Namespace: "tenant-a"}},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "steal", Namespace: "tenant-a"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, ResourceNames: []string{"victim-token"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "steal"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		}},
	}
	if !reachable(Build(inv), "User/alice", "ClusterAdmin/*") {
		t.Fatal("secret access did not reach the token identity")
	}
	for _, resource := range []string{"*/token", "serviceaccounts/token"} {
		inv.Roles[0].Rules = []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{resource}, Verbs: []string{"create"}, ResourceNames: []string{"victim"},
		}}
		g := Build(inv)
		if !reachable(g, "User/alice", "ClusterAdmin/*") {
			t.Fatalf("named %s did not reach the SA", resource)
		}
		for _, edge := range g.Out["Role/tenant-a/steal"] {
			if edge.Kind == EdgeCanTokenRequest && edge.To == "ServiceAccount/tenant-a/other" {
				t.Fatal("name-restricted TokenRequest reached another SA")
			}
		}
	}
	inv.Roles[0].Rules = []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, Verbs: []string{"impersonate"}, ResourceNames: []string{"victim"},
	}}
	if !reachable(Build(inv), "User/alice", "ClusterAdmin/*") {
		t.Fatal("named impersonation used an orphan SA ID")
	}
}

func TestEffectivePermissionsAndAdmissionPaths(t *testing.T) {
	g := Build(&scanner.Inventory{Pods: []corev1.Pod{privilegedPod("target")}})
	me := AddIdentity(g, "system:serviceaccount:tenant-a:reviewer", nil, nil, nil, nil)
	AugmentGraph(g, me, []CanDoResult{{Namespace: "tenant-a", Allowed: true, Check: CanDoCheck{
		Verb: "create", Resource: "pods", Subresource: "exec", Label: "exec into pods", HV: true,
	}}})
	if !reachable(g, me, "Node/worker-1") {
		t.Fatal("SSAR exec result remained a synthetic dead end")
	}
	AugmentPodCreation(g, me, []scanner.PodAdmissionResult{{
		Namespace: "tenant-a", Technique: "privileged-hostpid", NodeName: "master-1",
		ControlPlane: true, Status: scanner.AdmissionAdmitted,
	}})
	if !reachable(g, me, "Node/master-1") {
		t.Fatal("admitted control-plane-targeted template was missing")
	}
	if reachable(g, me, "ClusterAdmin/*") {
		t.Fatal("admission acceptance became fabricated cluster-admin")
	}
	findings := ToFindings(FindFrom(g, []string{me}, 6), false)
	for _, finding := range findings {
		if finding.AttackPath == nil || len(finding.AttackPath.Nodes) < 2 ||
			finding.AttackPath.Nodes[0].ID != me || !finding.AttackPath.Nodes[len(finding.AttackPath.Nodes)-1].HighValue {
			t.Fatalf("structured graph evidence missing: %+v", finding)
		}
	}
	data, err := json.Marshal(Snapshot(NewGraph(), nil, ""))
	if err != nil || strings.Contains(string(data), `"edges":null`) || strings.Contains(string(data), `"nodes":null`) {
		t.Fatalf("empty graph must encode arrays: %s (%v)", data, err)
	}
}
