package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func namespaceAdminFixture(t *testing.T, resolveIdentity, rejectAdmission, failAuthorization bool, extras ...func(http.ResponseWriter, *http.Request) bool) (*kubectx.Session, func() int) {
	t.Helper()
	var mu sync.Mutex
	podPosts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for _, handle := range extras {
			if handle(w, r) {
				return
			}
		}
		forbidden := func() {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(metav1.Status{
				TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
				Status:   metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden,
				Message: "namespace-scoped fixture cannot perform this operation",
			})
		}
		if r.Method == http.MethodDelete || r.Method == http.MethodPatch || r.Method == http.MethodPut {
			t.Errorf("unexpected mutation: %s %s", r.Method, r.URL)
			forbidden()
			return
		}
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
			if !resolveIdentity {
				forbidden()
				return
			}
			json.NewEncoder(w).Encode(authnv1.SelfSubjectReview{Status: authnv1.SelfSubjectReviewStatus{
				UserInfo: authnv1.UserInfo{Username: "system:serviceaccount:tenant-a:reviewer", Groups: []string{"system:authenticated"}},
			}})
		case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			if failAuthorization {
				forbidden()
				return
			}
			var review authzv1.SelfSubjectAccessReview
			if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
				t.Error(err)
			}
			attributes := review.Spec.ResourceAttributes
			review.Status.Allowed = attributes != nil && attributes.Namespace == "tenant-a" &&
				attributes.Group == "" && attributes.Resource == "pods" &&
				attributes.Verb == "create" && attributes.Subresource == ""
			json.NewEncoder(w).Encode(review)
		case "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
			if failAuthorization {
				forbidden()
				return
			}
			json.NewEncoder(w).Encode(authzv1.SelfSubjectRulesReview{
				Status: authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{{
					APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"},
				}}},
			})
		case "/api/v1/namespaces", "/api/v1/pods":
			forbidden()
		case "/api/v1/namespaces/tenant-a":
			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"}}
			if rejectAdmission {
				namespace.Labels = map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}
			}
			json.NewEncoder(w).Encode(namespace)
		case "/api/v1/namespaces/tenant-a/pods":
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode(corev1.PodList{})
				return
			}
			mu.Lock()
			podPosts++
			mu.Unlock()
			if r.URL.Query().Get("dryRun") != "All" {
				t.Errorf("non-dry-run pod creation: %s", r.URL)
			}
			if rejectAdmission {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(metav1.Status{
					TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
					Status:   metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden,
					Message: `pods "probe" is forbidden: violates PodSecurity "restricted:latest": privileged`,
				})
				return
			}
			var pod corev1.Pod
			json.NewDecoder(r.Body).Decode(&pod)
			json.NewEncoder(w).Encode(pod)
		case "/api/v1/nodes":
			json.NewEncoder(w).Encode(corev1.NodeList{Items: []corev1.Node{{
				ObjectMeta: metav1.ObjectMeta{Name: "master-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}},
			}}})
		case "/api":
			json.NewEncoder(w).Encode(metav1.APIVersions{Versions: []string{"v1"}})
		case "/apis":
			json.NewEncoder(w).Encode(metav1.APIGroupList{})
		case "/api/v1":
			json.NewEncoder(w).Encode(metav1.APIResourceList{GroupVersion: "v1"})
		default:
			w.Write([]byte(`{"items":[]}`))
		}
	}))
	t.Cleanup(server.Close)
	cfg := &rest.Config{Host: server.URL, QPS: 1000, Burst: 1000}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &kubectx.Session{
		Info: kubectx.ContextInfo{
			Name: "fixture", Namespace: "tenant-a", UserName: "kubeconfig-alias", ClusterName: "fixture",
		},
		RestCfg: cfg, Client: client, Discovery: client.Discovery(),
	}, func() int {
		mu.Lock()
		defer mu.Unlock()
		return podPosts
	}
}

func TestNamedEphemeralAuthorizationWithoutRoleListWorksInDiscoverAndScan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, mode := range []string{"discover", "scan"} {
		t.Run(mode, func(t *testing.T) {
			sess, posts := namespaceAdminFixture(t, true, false, false, func(w http.ResponseWriter, r *http.Request) bool {
				switch r.URL.Path {
				case "/api/v1/namespaces/tenant-a/pods":
					if r.Method != http.MethodGet {
						return false
					}
					json.NewEncoder(w).Encode(corev1.PodList{Items: []corev1.Pod{{
						ObjectMeta: metav1.ObjectMeta{Name: "debug-target", Namespace: "tenant-a"},
						Spec:       corev1.PodSpec{HostPID: true, NodeName: "worker-1", Containers: []corev1.Container{{Name: "app"}}},
						Status:     corev1.PodStatus{Phase: corev1.PodRunning},
					}}})
					return true
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					var review authzv1.SelfSubjectAccessReview
					json.NewDecoder(r.Body).Decode(&review)
					attributes := review.Spec.ResourceAttributes
					review.Status.Allowed = attributes != nil && attributes.Group == "" && attributes.Resource == "pods" &&
						attributes.Namespace == "tenant-a" && attributes.Name == "debug-target" &&
						attributes.Subresource == "ephemeralcontainers" && attributes.Verb == "update"
					json.NewEncoder(w).Encode(review)
					return true
				case "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
					json.NewEncoder(w).Encode(authzv1.SelfSubjectRulesReview{
						Status: authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{{
							APIGroups: []string{""}, Resources: []string{"pods/ephemeralcontainers"},
							Verbs: []string{"update"}, ResourceNames: []string{"debug-target"},
						}}},
					})
					return true
				}
				return false
			})
			report, err := executeSession(context.Background(), Options{Mode: mode, SkipExploit: true}, sess, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range report.Findings {
				if finding.RuleID == "KH-RBAC-EPHEMERAL" {
					found = true
					if !strings.Contains(finding.Evidence, "create pods/exec=denied") || finding.Exploit != nil || finding.Shell != nil {
						t.Fatal("injection authorization became successful exec")
					}
				}
			}
			if !found || posts() != 0 {
				t.Fatalf("ephemeral check missing or created a pod: found=%t posts=%d", found, posts())
			}
			potential := false
			for _, node := range report.Graph.Nodes {
				potential = potential || (node.Kind == "EphemeralCandidate" && node.Status == "potential")
			}
			if !potential {
				t.Fatal("named ephemeral authorization did not survive graph/path reporting")
			}
		})
	}
}

func TestEmptyNamespaceAdminScanFindsProspectiveControlPlaneRisk(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, resolved := range []bool{true, false} {
		t.Run(map[bool]string{true: "resolved-identity", false: "identity-fallback"}[resolved], func(t *testing.T) {
			sess, posts := namespaceAdminFixture(t, resolved, false, false)
			report, err := executeSession(context.Background(), Options{Mode: "scan", SkipExploit: true}, sess, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if posts() != 4 || report.Graph == nil || len(report.Graph.Edges) == 0 {
				t.Fatalf("prospective graph missing: posts=%d graph=%+v", posts(), report.Graph)
			}
			if !report.Metadata.SafetyGuard || len(report.Metadata.SafetyViolations) != 0 {
				t.Fatalf("safety guard failed: %+v", report.Metadata)
			}
			foundControlPlane, foundPath := false, false
			for _, finding := range report.Findings {
				if finding.RuleID == "KH-ESC-POD-CREATE" && strings.Contains(finding.Evidence, "node=master-1") {
					foundControlPlane = true
					if finding.Severity != scanner.SevCritical || finding.Exploit != nil {
						t.Fatalf("admission confidence was misstated: %+v", finding)
					}
				}
				if finding.AttackPath != nil {
					for _, node := range finding.AttackPath.Nodes {
						foundPath = foundPath || node.ID == "Node/master-1"
						if node.Kind == "ClusterAdmin" {
							t.Fatal("namespace admin became a fabricated cluster-admin")
						}
					}
				}
			}
			if !foundControlPlane || !foundPath {
				t.Fatalf("empty namespace escalation was missed: controlPlane=%t path=%t", foundControlPlane, foundPath)
			}
			if resolved && report.Identity.Username != "system:serviceaccount:tenant-a:reviewer" {
				t.Fatalf("kubeconfig alias overrode the actual identity: %+v", report.Identity)
			}
		})
	}
}

func TestDiscoverRetainsCapabilityWithoutPodPOST(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sess, posts := namespaceAdminFixture(t, true, false, false)
	report, err := executeSession(context.Background(), Options{Mode: "discover"}, sess, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if posts() != 0 || report.Graph == nil || len(report.Graph.Edges) == 0 {
		t.Fatalf("discovery posts=%d graph=%+v", posts(), report.Graph)
	}
	if report.Metadata.EscapePosture != "unknown" {
		t.Fatalf("unverified admission became a clean escape posture: %s", report.Metadata.EscapePosture)
	}
}

func TestRestrictedAdmissionDoesNotBecomeConfirmedEscape(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sess, _ := namespaceAdminFixture(t, true, true, false)
	report, err := executeSession(context.Background(), Options{Mode: "scan", SkipExploit: true}, sess, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "KH-ESC-POD-CREATE" {
			t.Fatalf("denied admission became an escape capability: %+v", finding)
		}
	}
	for _, edge := range report.Graph.Edges {
		if edge.Kind == "CanEscape" {
			t.Fatalf("denied admission became host access: %+v", edge)
		}
	}
}

func TestFailedAuthorizationIsNotAZeroRiskResult(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sess, posts := namespaceAdminFixture(t, true, false, true)
	report, err := executeSession(context.Background(), Options{Mode: "discover"}, sess, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Metadata.Incomplete || report.Metadata.EscapePosture != "unknown" || posts() != 0 {
		t.Fatalf("failed authorization was presented as complete: %+v", report.Metadata)
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "KH-IDENT-CANDO" && !strings.Contains(finding.Description, "unknown") {
			t.Fatalf("failed probes were described as denial: %+v", finding)
		}
	}
}

func TestUnresolvedOperatorDoesNotMergeWithKubeconfigAliasBinding(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sess, _ := namespaceAdminFixture(t, false, false, false, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/apis/rbac.authorization.k8s.io/v1/clusterroles":
			json.NewEncoder(w).Encode(rbacv1.ClusterRoleList{Items: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			}}})
		case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
			json.NewEncoder(w).Encode(rbacv1.ClusterRoleBindingList{Items: []rbacv1.ClusterRoleBinding{{
				ObjectMeta: metav1.ObjectMeta{Name: "alias-admin"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "kubeconfig-alias"}},
			}}})
		default:
			return false
		}
		return true
	})
	report, err := executeSession(context.Background(), Options{Mode: "discover"}, sess, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(report.Graph.Me, "Operator/") {
		t.Fatalf("unknown credentials merged with a named RBAC subject: %s", report.Graph.Me)
	}
	for _, finding := range report.Findings {
		if finding.AttackPath == nil || len(finding.AttackPath.Nodes) == 0 ||
			finding.AttackPath.Nodes[0].ID != report.Graph.Me {
			continue
		}
		for _, node := range finding.AttackPath.Nodes {
			if node.Kind == "ClusterAdmin" {
				t.Fatal("kubeconfig alias fabricated current-operator cluster-admin")
			}
		}
	}
}

func TestEscapeGraphPathContributesToPosture(t *testing.T) {
	finding := scanner.Finding{
		RuleID: "KH-PATH-001", Severity: scanner.SevHigh,
		AttackPath: &scanner.GraphSnapshot{Edges: []scanner.GraphEdge{{Kind: "CanEscape"}}},
	}
	if posture := computeEscapePosture([]scanner.Finding{finding}); posture != "vulnerable" {
		t.Fatalf("graph escape path became clean posture: %s", posture)
	}
}
