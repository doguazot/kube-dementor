package engine

import (
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/authcheck"
	"github.com/kube-dementor/kube-dementor/pkg/converter"
	"github.com/kube-dementor/kube-dementor/pkg/ingestor"
	"github.com/kube-dementor/kube-dementor/pkg/models"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func legacyFixture() *ingestor.RawClusterData {
	privileged := true
	root := int64(0)
	return &ingestor.RawClusterData{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "tenant-a", UID: "pod-1"},
			Spec: corev1.PodSpec{
				NodeName: "worker-1", HostPID: true, ServiceAccountName: "runner",
				Containers: []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{
					Privileged: &privileged, RunAsUser: &root,
				}}},
			},
		}},
		ServiceAccounts: []corev1.ServiceAccount{{
			ObjectMeta: metav1.ObjectMeta{Name: "runner", Namespace: "tenant-a", UID: "sa-1"},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "exec-one", Namespace: "tenant-a", UID: "role-1"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}, ResourceNames: []string{"target"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "exec", Namespace: "tenant-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "exec-one"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}, {Kind: "Group", Name: "reviewers"}},
		}},
	}
}

func TestLegacyHumanExecAndHostPIDEscapeWithoutNodeList(t *testing.T) {
	data := converter.New().Convert(legacyFixture())
	edges := New().Analyze(data, nil)
	execEdges, escapes := 0, 0
	for _, edge := range edges {
		switch edge.Type {
		case models.EdgePodExec:
			execEdges++
			if edge.Properties["namespace"] != "tenant-a" {
				t.Fatal("pod exec lost its namespace")
			}
		case models.EdgeCENsenter:
			escapes++
		}
	}
	if execEdges != 2 || escapes != 1 || len(data.Nodes) != 1 || !data.Nodes[0].Partial {
		t.Fatalf("human/group access or partial-node escape lost: exec=%d escapes=%d nodes=%+v", execEdges, escapes, data.Nodes)
	}
	raw := legacyFixture()
	raw.Roles[0].Rules[0].ResourceNames = []string{"other"}
	for _, edge := range New().Analyze(converter.New().Convert(raw), nil) {
		if edge.Type == models.EdgePodExec {
			t.Fatal("named exec permission reached another pod")
		}
	}
	raw.Roles[0].Rules[0].ResourceNames = nil
	raw.Roles[0].Rules[0].APIGroups = []string{"custom.example"}
	for _, edge := range New().Analyze(converter.New().Convert(raw), nil) {
		if edge.Type == models.EdgePodExec {
			t.Fatal("custom API-group permission reached a core pod")
		}
	}
}

func TestLegacyEmptyNamespaceAdminHasPodCreationNotClusterAdmin(t *testing.T) {
	raw := &ingestor.RawClusterData{
		ClusterRoles: []rbacv1.ClusterRole{{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", UID: "admin-role"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "local-admin", Namespace: "tenant-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		}},
	}
	data := converter.New().Convert(raw)
	foundCreate := false
	for _, edge := range New().Analyze(data, nil) {
		foundCreate = foundCreate || edge.Type == models.EdgePodCreate
		if edge.Type == models.EdgeRoleBind {
			t.Fatal("namespace-admin binding was labeled full cluster-admin")
		}
	}
	if !foundCreate || len(data.Actions) == 0 {
		t.Fatal("empty namespace pod creation capability was missed")
	}
}

func TestLegacyTokenAutomountAndEphemeralContainers(t *testing.T) {
	raw := legacyFixture()
	disabled := false
	raw.ServiceAccounts[0].AutomountServiceAccountToken = &disabled
	raw.ClusterRoles = []rbacv1.ClusterRole{{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", UID: "admin-role"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	}}
	raw.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "runner", Namespace: "tenant-a"}},
	}}
	for _, edge := range New().Analyze(converter.New().Convert(raw), nil) {
		if edge.Type == models.EdgeTokenSteal {
			t.Fatal("SA-level disabled automount became mounted token theft")
		}
	}
	privileged := true
	root := int64(0)
	raw.Pods[0].Spec.Containers[0].SecurityContext = nil
	raw.Pods[0].Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: "debug", SecurityContext: &corev1.SecurityContext{Privileged: &privileged, RunAsUser: &root},
			VolumeMounts: []corev1.VolumeMount{{Name: "token", MountPath: "/token"}},
		},
	}}
	raw.Pods[0].Spec.Volumes = []corev1.Volume{{
		Name: "token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}},
		}},
	}}
	data := converter.New().Convert(raw)
	token, escape := false, false
	for _, edge := range New().Analyze(data, nil) {
		token = token || edge.Type == models.EdgeTokenSteal
		escape = escape || edge.Type == models.EdgeCENsenter
	}
	if !token || !escape || len(data.Containers) != 2 {
		t.Fatalf("projected token or ephemeral escape lost: token=%t escape=%t containers=%d", token, escape, len(data.Containers))
	}
}

func legacyReachable(edges []models.Edge, start, target string) bool {
	queue, seen := []string{start}, map[string]bool{start: true}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == target {
			return true
		}
		for _, edge := range edges {
			if edge.Type != models.EdgeHasPermission && edge.SourceUID == current && !seen[edge.TargetUID] {
				seen[edge.TargetUID] = true
				queue = append(queue, edge.TargetUID)
			}
		}
	}
	return false
}

func TestLegacyServiceAccountInheritsGuaranteedGroupGrant(t *testing.T) {
	raw := legacyFixture()
	raw.ClusterRoles = []rbacv1.ClusterRole{{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", UID: "admin-role"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	}}
	raw.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:serviceaccounts:tenant-a"}},
	}}
	edges := New().Analyze(converter.New().Convert(raw), nil)
	if !legacyReachable(edges, "identity/User//alice", "admin-role") {
		t.Fatal("pod token could not reach its SA's inherited group grant")
	}
}

func TestLegacyAdmissionIsOperatorScopedAndRuntimeUnchecked(t *testing.T) {
	data := converter.New().Convert(&ingestor.RawClusterData{
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "create", Namespace: "team", UID: "role-create"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "create"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}, {Kind: "User", Name: "bob"}},
		}},
	})
	data.Actions = []models.ActionNode{{
		UID: "admitted-probe", Name: "privileged specification", Namespace: "team", Kind: "PodTemplate",
		Admission: "admitted", OwnerUID: "identity/User//alice",
	}}
	edges := New().Analyze(data, &authcheck.UserPerms{User: "alice"})
	if !legacyReachable(edges, "identity/User//alice", "admitted-probe") ||
		legacyReachable(edges, "identity/User//bob", "admitted-probe") {
		t.Fatal("operator-specific admission was shared with another pod creator")
	}
	potential := false
	for _, edge := range edges {
		if edge.Type == models.EdgePodCreateEscape {
			potential = true
			if edge.Properties["exploitable"] != "UNCHECKED" {
				t.Fatalf("untested runtime became a denial: %+v", edge)
			}
			if edge.TargetUID != "action/node-access/team" {
				t.Fatalf("unplaced spec invented a discovered node: %+v", edge)
			}
		}
	}
	if !potential {
		t.Fatal("generic admitted specification lost its potential escape path")
	}
}
