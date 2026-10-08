package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func ephemeralFixturePod(name string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-a"},
		Spec:       corev1.PodSpec{NodeName: "worker-1", HostPID: true, Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func ephemeralFixtureClient(t *testing.T, decide func(*authzv1.ResourceAttributes) authzv1.SubjectAccessReviewStatus) kubernetes.Interface {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			t.Errorf("unexpected mutation/exec request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var review authzv1.SelfSubjectAccessReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			t.Error(err)
		}
		attributes := review.Spec.ResourceAttributes
		if attributes == nil || attributes.Resource != "pods" || attributes.Group != "" {
			t.Errorf("wrong authorization attributes: %+v", attributes)
		}
		review.Status = decide(attributes)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(review)
	}))
	t.Cleanup(server.Close)
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: 1000, Burst: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestEphemeralAssessmentRetainsNamedTargetsNamespaceAndSeparateExecAttach(t *testing.T) {
	client := ephemeralFixtureClient(t, func(attributes *authzv1.ResourceAttributes) authzv1.SubjectAccessReviewStatus {
		return authzv1.SubjectAccessReviewStatus{Allowed: attributes.Namespace == "tenant-a" && attributes.Name == "target" &&
			((attributes.Subresource == "ephemeralcontainers" && attributes.Verb == "update") ||
				(attributes.Subresource == "attach" && attributes.Verb == "create"))}
	})
	otherNS := ephemeralFixturePod("target")
	otherNS.Namespace = "tenant-b"
	inv := &Inventory{
		Pods:  []corev1.Pod{ephemeralFixturePod("target"), ephemeralFixturePod("other"), otherNS},
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", Labels: map[string]string{"node-role.kubernetes.io/worker": ""}}}},
	}
	results := AssessEphemeralContainers(context.Background(), client, inv)
	allowed := 0
	for _, result := range results {
		if !result.CanInject() {
			continue
		}
		allowed++
		if result.Namespace != "tenant-a" || result.PodName != "target" || result.NodeRole != "worker" {
			t.Fatalf("authorization or placement leaked: %+v", result)
		}
		if result.Permissions["create pods/exec"].Allowed || !result.Permissions["create pods/attach"].Allowed {
			t.Fatal("injection/attach fabricated exec permission")
		}
	}
	if allowed != 1 {
		t.Fatalf("named allowed targets=%d", allowed)
	}
	graph := EphemeralPotentialGraph(results, "Operator/me")
	for _, node := range graph.Nodes {
		if node.ID != "Operator/me" && node.Status != "potential" {
			t.Fatal("authorization became an execution success")
		}
		if strings.Contains(node.ID, "tenant-b") || node.Kind == "ClusterAdmin" {
			t.Fatal("named authorization created cross-namespace or cluster-admin access")
		}
	}
}

func TestExistingEphemeralStateAndInheritedSecurityAreNotActiveShellProof(t *testing.T) {
	privileged, nonroot := true, true
	pod := ephemeralFixturePod("target")
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: &nonroot}
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: "debug", SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
		},
		TargetContainerName: "app",
	}}
	pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{
		Name: "debug", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	client := ephemeralFixtureClient(t, func(attributes *authzv1.ResourceAttributes) authzv1.SubjectAccessReviewStatus {
		return authzv1.SubjectAccessReviewStatus{Allowed: attributes.Subresource == "exec" && attributes.Verb == "create"}
	})
	inv := &Inventory{Pods: []corev1.Pod{pod}}
	results := AssessEphemeralContainers(context.Background(), client, inv)
	if results[0].CanInject() || results[0].Containers[0].EscapeConditions != "" {
		t.Fatal("exec privilege or inherited nonroot fabricated privileged-root injection")
	}
	graph := EphemeralPotentialGraph(results, "Operator/me")
	if len(graph.Nodes) != 2 {
		t.Fatalf("running debug target without root became host access: %+v", graph)
	}
	pod.Spec.SecurityContext = nil
	inv.Pods = []corev1.Pod{pod}
	results = AssessEphemeralContainers(context.Background(), client, inv)
	if results[0].NodeRole != "unknown" || results[0].Containers[0].EscapeConditions == "" {
		t.Fatal("hidden node role was invented or debug security was missed")
	}
	for _, state := range []corev1.ContainerState{
		{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
		{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}},
		{},
	} {
		inv.Pods[0].Status.EphemeralContainerStatuses[0].State = state
		results = AssessEphemeralContainers(context.Background(), client, inv)
		if len(EphemeralPotentialGraph(results, "Operator/me").Edges) != 0 {
			t.Fatal("stopped or unknown debug container became an exec target")
		}
		for _, finding := range EphemeralFindings(results) {
			if finding.Shell != nil || finding.Exploit != nil || (finding.RuleID == "KH-WRK-EPHEMERAL" && finding.Severity != SevInfo) {
				t.Fatal("historical debug settings became live shell/escape evidence")
			}
		}
	}
}

func TestEphemeralUnknownAndEmptyNamespaceDoNotInventTargets(t *testing.T) {
	client := ephemeralFixtureClient(t, func(attributes *authzv1.ResourceAttributes) authzv1.SubjectAccessReviewStatus {
		return authzv1.SubjectAccessReviewStatus{EvaluationError: "fixture authorization unavailable"}
	})
	inv := &Inventory{NamespaceTargets: []string{"tenant-a"}}
	results := AssessEphemeralContainers(context.Background(), client, inv)
	if len(results) != 1 || results[0].CanInject() || len(EphemeralCollectionIssues(results)) != 2 {
		t.Fatalf("missing authorization was treated as denial/success: %+v", results)
	}
	encoded, err := json.Marshal(EphemeralFindings(results))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "unknown: fixture authorization unavailable") {
		t.Fatal("unknown permission status disappeared")
	}
	client = ephemeralFixtureClient(t, func(attributes *authzv1.ResourceAttributes) authzv1.SubjectAccessReviewStatus {
		return authzv1.SubjectAccessReviewStatus{Allowed: true}
	})
	results = AssessEphemeralContainers(context.Background(), client, inv)
	if !results[0].CanInject() || len(EphemeralPotentialGraph(results, "Operator/me").Nodes) != 0 {
		t.Fatal("namespace permission invented a running debug target")
	}
}

func TestEphemeralAssessmentMakesOnlyAuthorizationRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			t.Errorf("unexpected mutation/exec request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var review authzv1.SelfSubjectAccessReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			t.Error(err)
		}
		review.Status.Allowed = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(review)
	}))
	defer server.Close()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: 1000, Burst: 1000})
	if err != nil {
		t.Fatal(err)
	}
	results := AssessEphemeralContainers(context.Background(), client, &Inventory{Pods: []corev1.Pod{ephemeralFixturePod("target")}})
	if len(results) != 1 || !results[0].CanInject() || !results[0].CanInteract() {
		t.Fatalf("named authorization result lost: %+v", results)
	}
}
