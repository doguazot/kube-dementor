package rules

import (
	"strings"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBoundBuiltinAdminAndCustomAdminRolesAreEvaluated(t *testing.T) {
	rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}}
	inv := &scanner.Inventory{ClusterRoles: []rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: "admin"}, Rules: rules}}}
	if len(ruleRBAC007PodCreate(inv, nil)) != 0 {
		t.Fatal("unbound built-in admin template became a finding")
	}
	inv.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "local-admin", Namespace: "tenant-a"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "admin"},
	}}
	if len(ruleRBAC007PodCreate(inv, nil)) != 1 {
		t.Fatal("bound built-in admin capability was skipped")
	}
	inv.ClusterRoles, inv.RoleBindings = nil, nil
	inv.Roles = []rbacv1.Role{{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "tenant-a"}, Rules: rules}}
	if len(ruleRBAC007PodCreate(inv, nil)) != 1 {
		t.Fatal("custom namespace Role named admin was skipped")
	}
	inv.Roles[0].Rules[0].Verbs = []string{"patch"}
	findings := ruleRBAC007PodCreate(inv, nil)
	if len(findings) != 1 || strings.Contains(findings[0].Title, "create") || !strings.Contains(findings[0].Impact, "immutable") {
		t.Fatalf("pod patch was equated with arbitrary creation: %+v", findings)
	}
}

func TestPullSecretReferenceIsNotContainerCredentialExposure(t *testing.T) {
	inv := &scanner.Inventory{
		ServiceAccounts: []corev1.ServiceAccount{{
			ObjectMeta:       metav1.ObjectMeta{Name: "runner", Namespace: "tenant-a"},
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "registry"}},
		}},
		Secrets: []corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{Name: "registry", Namespace: "tenant-a"},
			Type:       corev1.SecretTypeDockerConfigJson,
			Data:       map[string][]byte{".dockerconfigjson": []byte(`{"auths":{"registry.example":{"username":"fixture"}}}`)},
		}},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant-a"},
			Spec:       corev1.PodSpec{ServiceAccountName: "runner", Containers: []corev1.Container{{Name: "app"}}},
		}},
	}
	if len(ruleSAPullSecret(inv, nil)) != 0 {
		t.Fatal("imagePullSecrets alone became credential theft")
	}
	inv.Pods[0].Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{
		SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "registry"}},
	}}
	if len(ruleSAPullSecret(inv, nil)) != 1 {
		t.Fatal("explicitly exposed registry credential was missed")
	}
}

func TestCorePatternRequiresSameRootCapableContainerAndWritableTarget(t *testing.T) {
	root, nonroot := int64(0), int64(10001)
	container := corev1.Container{Name: "app", SecurityContext: &corev1.SecurityContext{
		RunAsUser: &root, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}},
	}, VolumeMounts: []corev1.VolumeMount{{Name: "host", MountPath: "/host"}}}
	pod := corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{container},
		Volumes:    []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}}},
	}}
	inv := &scanner.Inventory{Pods: []corev1.Pod{pod}}
	if len(ruleCorePattern(inv, nil)) != 1 {
		t.Fatal("parent host-root mount was missed")
	}
	inv.Pods[0].Spec.Volumes[0].HostPath.Path = "/proc/cpuinfo"
	if len(ruleCorePattern(inv, nil)) != 0 {
		t.Fatal("unrelated proc descendant became core_pattern access")
	}
	inv.Pods[0].Spec.Volumes[0].HostPath.Path = "/proc/sys/kernel/core_pattern"
	inv.Pods[0].Spec.Containers[0].VolumeMounts[0].ReadOnly = true
	if len(ruleCorePattern(inv, nil)) != 0 {
		t.Fatal("read-only core_pattern mount became host RCE")
	}
	inv.Pods[0].Spec.Containers[0].VolumeMounts[0].ReadOnly = false
	inv.Pods[0].Spec.Containers[0].SecurityContext.RunAsUser = &nonroot
	inv.Pods[0].Spec.Containers = append(inv.Pods[0].Spec.Containers, corev1.Container{
		Name: "root-without-capability", SecurityContext: &corev1.SecurityContext{RunAsUser: &root},
	})
	if len(ruleCorePattern(inv, nil)) != 0 || len(ruleCgroupReleaseAgent(inv, nil)) != 0 {
		t.Fatal("root and capability from separate containers were combined")
	}
}

func TestRuntimeAdvisoriesInspectEveryNode(t *testing.T) {
	inv := &scanner.Inventory{Nodes: []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "patched"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{ContainerRuntimeVersion: "containerd://1.7.30"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "old"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{ContainerRuntimeVersion: "containerd://1.5.9"}}},
	}}
	for _, rule := range EscapeRules() {
		if rule.ID != "KH-ESC-CTRD-2022-23648" {
			continue
		}
		findings := rule.Fn(inv, nil)
		if len(findings) != 1 || findings[0].Resource.Name != "old" {
			t.Fatalf("patched first node hid vulnerable second node: %+v", findings)
		}
	}
}

func TestSubresourceWildcardAndCrossNamespaceClusterRole(t *testing.T) {
	rule := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"*/token"}, Verbs: []string{"create"}}
	if !hasSubresource(rule, "serviceaccounts", "token") {
		t.Fatal("valid subresource wildcard was missed")
	}
	rule.APIGroups = []string{"custom.example"}
	if hasSubresource(rule, "serviceaccounts", "token") {
		t.Fatal("custom API-group permission was treated as core TokenRequest")
	}
	inv := &scanner.Inventory{
		ClusterRoles: []rbacv1.ClusterRole{{
			ObjectMeta: metav1.ObjectMeta{Name: "secret-reader"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "tenant-b"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
		}},
		RoleBindings: []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "cross-ns", Namespace: "tenant-b"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "secret-reader"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "runner", Namespace: "tenant-a"}},
		}},
	}
	if len(ruleSEC011CrossNSSecret(inv, nil)) != 1 {
		t.Fatal("ClusterRole reference was resolved as a same-named local Role")
	}
}

func TestEphemeralRoleFindingDoesNotPromisePrivilegedAdmissionOrIgnoreNames(t *testing.T) {
	inv := &scanner.Inventory{Roles: []rbacv1.Role{{
		ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "team"},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/ephemeralcontainers"},
			Verbs: []string{"patch"}, ResourceNames: []string{"target"}}},
	}}}
	findings := ruleRBAC014EphemeralContainers(inv, nil)
	if len(findings) != 1 || !strings.Contains(findings[0].Evidence, "resourceNames=[target]") ||
		!strings.Contains(findings[0].Description, "Pod-level security settings still apply") {
		t.Fatalf("ephemeral authorization overstated: %+v", findings)
	}
	inv.Roles[0].Rules[0].APIGroups = []string{"custom.example"}
	if len(ruleRBAC014EphemeralContainers(inv, nil)) != 0 {
		t.Fatal("custom API group fabricated core ephemeralcontainer permission")
	}
}
