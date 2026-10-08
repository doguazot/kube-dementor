package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodAdmissionUsesOnlyDryRunAndNeverExecutes(t *testing.T) {
	requests := 0
	sess := inventoryTestSession(t, "tenant-a", func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/namespaces/tenant-a/pods" {
			t.Errorf("unexpected admission request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected", http.StatusBadRequest)
			return true
		}
		if r.URL.Query().Get("dryRun") != metav1.DryRunAll {
			t.Errorf("pod CREATE was not dry-run: %s", r.URL)
		}
		requests++
		var pod corev1.Pod
		if err := json.NewDecoder(r.Body).Decode(&pod); err != nil {
			t.Error(err)
		}
		if pod.Spec.Containers[0].Image != "registry.k8s.io/pause:3.10" || len(pod.Spec.Containers[0].Command) != 0 {
			t.Error("admission probe must not contain an exploit command")
		}
		json.NewEncoder(w).Encode(pod)
		return true
	})
	guarded, guard, err := kubectx.WrapSessionReadOnly(sess)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []corev1.Node{{ObjectMeta: metav1.ObjectMeta{
		Name: "control-plane-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
	}}}
	results := AssessPodCreation(context.Background(), guarded.Client, []string{"tenant-a", "tenant-a"}, nodes, true)
	if requests != 4 || len(results) != 4 {
		t.Fatalf("requests=%d results=%d, want 4", requests, len(results))
	}
	for _, result := range results {
		if result.Status != AdmissionAdmitted {
			t.Fatalf("expected admitted result: %+v", result)
		}
	}
	if len(guard.Violations()) != 0 {
		t.Fatalf("mutation guard intercepted admission checks: %+v", guard.Violations())
	}
	findings := PodCreationFindings(results)
	if len(findings) != 4 {
		t.Fatalf("findings=%d, want 4", len(findings))
	}
	for _, finding := range findings {
		if finding.Exploit != nil {
			t.Fatal("admission must not count as a verified exploit")
		}
		if !strings.Contains(finding.Impact, "does not prove") {
			t.Fatal("admission finding overstated proof")
		}
	}
}

func TestPodAdmissionDeniedUnknownAndMutated(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status AdmissionStatus
		handle func(http.ResponseWriter, *http.Request)
	}{
		{"policy-denied", AdmissionDenied, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(metav1.Status{
				TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
				Status:   metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden,
				Message: `pods "probe" is forbidden: violates PodSecurity "restricted:latest": privileged`,
			})
		}},
		{"quota-inconclusive", AdmissionUnknown, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(metav1.Status{
				TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
				Status:   metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden,
				Message: "pods is forbidden: failed quota: required-resources: must specify limits.cpu",
			})
		}},
		{"authorization-inconclusive", AdmissionUnknown, func(w http.ResponseWriter, _ *http.Request) {
			inventoryForbidden(w)
		}},
		{"unavailable", AdmissionUnknown, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(metav1.Status{
				TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
				Status:   metav1.StatusFailure, Reason: metav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable,
			})
		}},
		{"mutated-safe", AdmissionDenied, func(w http.ResponseWriter, r *http.Request) {
			var pod corev1.Pod
			json.NewDecoder(r.Body).Decode(&pod)
			privileged := false
			pod.Spec.Containers[0].SecurityContext.Privileged = &privileged
			json.NewEncoder(w).Encode(pod)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := inventoryTestSession(t, "tenant-a", func(w http.ResponseWriter, r *http.Request) bool {
				tc.handle(w, r)
				return true
			})
			results := AssessPodCreation(context.Background(), sess.Client, []string{"tenant-a"}, nil, true)
			for _, result := range results {
				if result.Status != tc.status {
					t.Fatalf("got %s, want %s: %+v", result.Status, tc.status, result)
				}
			}
			if tc.status == AdmissionDenied && len(PodCreationFindings(results)) != 0 {
				t.Fatal("denied dangerous specifications became escape findings")
			}
		})
	}
}

func TestDiscoveryDoesNotPostPodAdmissionChecks(t *testing.T) {
	sess := inventoryTestSession(t, "tenant-a", func(w http.ResponseWriter, r *http.Request) bool {
		t.Errorf("discovery made a pod request: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusBadRequest)
		return true
	})
	results := AssessPodCreation(context.Background(), sess.Client, []string{"tenant-a"}, nil, false)
	if len(results) != 2 || results[0].Status != AdmissionUnknown {
		t.Fatalf("missing prospective capability: %+v", results)
	}
}

func TestAutomountTokenInheritanceAndExplicitProjection(t *testing.T) {
	for _, tc := range []struct {
		sa, pod *bool
		want    bool
	}{
		{boolPointer(false), nil, false},
		{boolPointer(false), boolPointer(true), true},
		{boolPointer(true), boolPointer(false), false},
		{nil, nil, true},
	} {
		inv := &Inventory{ServiceAccounts: []corev1.ServiceAccount{{
			ObjectMeta:                   metav1.ObjectMeta{Name: "runner", Namespace: "tenant-a"},
			AutomountServiceAccountToken: tc.sa,
		}}}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a"},
			Spec:       corev1.PodSpec{ServiceAccountName: "runner", AutomountServiceAccountToken: tc.pod},
		}
		if got := HasServiceAccountToken(inv, pod); got != tc.want {
			t.Fatalf("token availability=%v, want %v", got, tc.want)
		}
		pod.Spec.AutomountServiceAccountToken = boolPointer(false)
		pod.Spec.Volumes = []corev1.Volume{{
			Name: "api-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}},
			}},
		}}
		pod.Spec.Containers = []corev1.Container{{Name: "runner", VolumeMounts: []corev1.VolumeMount{{Name: "api-token", MountPath: "/token"}}}}
		if !HasServiceAccountToken(inv, pod) {
			t.Fatal("explicit token projection was lost")
		}
	}
}

func TestEscapeRequiresActualContainerPrerequisites(t *testing.T) {
	root, nonroot := int64(0), int64(10001)
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		HostPID:         true,
		SecurityContext: &corev1.PodSecurityContext{RunAsUser: &nonroot},
		Containers: []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{
			Privileged: boolPointer(true), RunAsUser: &root,
		}}},
	}}
	if PodEscapeReason(pod) == "" {
		t.Fatal("container-level root override with privileged hostPID was missed")
	}
	pod.Spec.Containers[0].SecurityContext.RunAsUser = nil
	if PodEscapeReason(pod) != "" {
		t.Fatal("nonroot container became a root nsenter escape")
	}
	pod.Spec.SecurityContext = nil
	pod.Spec.Containers[0].SecurityContext = nil
	pod.Spec.HostNetwork = true
	if PodEscapeReason(pod) != "" {
		t.Fatal("host namespaces alone became host execution")
	}
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: "debug", SecurityContext: &corev1.SecurityContext{Privileged: boolPointer(true), RunAsUser: &root},
		},
	}}
	if PodEscapeReason(pod) == "" {
		t.Fatal("privileged ephemeral container was missed")
	}
}

func boolPointer(value bool) *bool { return &value }

func TestHostPathDescendantsAndSubPathEscape(t *testing.T) {
	for _, hostPath := range []string{"/etc/kubernetes/manifests", "/var/lib/kubelet/pki", "/etc/cron.d"} {
		if !DangerousHostPath(hostPath) {
			t.Fatalf("sensitive descendant %s was missed", hostPath)
		}
	}
	if DangerousHostPath("/tmp/application") {
		t.Fatal("ordinary host directory became a sensitive escape target")
	}
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{
			Name: "app", VolumeMounts: []corev1.VolumeMount{{Name: "host", MountPath: "/manifests", SubPath: "kubernetes/manifests"}},
		}},
		Volumes: []corev1.Volume{{
			Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}},
		}},
	}}
	if PodEscapeReason(pod) == "" {
		t.Fatal("subPath to static-pod manifests was missed")
	}
}
