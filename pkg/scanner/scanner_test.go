package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func inventoryTestSession(t *testing.T, namespace string, handle func(http.ResponseWriter, *http.Request) bool) *kubectx.Session {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if handle(w, r) {
			return
		}
		switch r.URL.Path {
		case "/api":
			json.NewEncoder(w).Encode(metav1.APIVersions{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIVersions"},
				Versions: []string{"v1"},
			})
		case "/apis":
			json.NewEncoder(w).Encode(metav1.APIGroupList{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroupList"},
			})
		case "/api/v1":
			json.NewEncoder(w).Encode(metav1.APIResourceList{
				TypeMeta:     metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
				GroupVersion: "v1",
			})
		default:
			w.Write([]byte(`{"items":[]}`))
		}
	}))
	t.Cleanup(server.Close)
	cfg := &rest.Config{Host: server.URL}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &kubectx.Session{
		Info:      kubectx.ContextInfo{Namespace: namespace},
		RestCfg:   cfg,
		Client:    client,
		Discovery: client.Discovery(),
	}
}

func inventoryForbidden(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Reason:   metav1.StatusReasonForbidden,
		Code:     http.StatusForbidden,
		Message:  "list is forbidden",
	})
}

func TestInventoryFallsBackToContextNamespace(t *testing.T) {
	sess := inventoryTestSession(t, "tenant-a", func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/namespaces", "/api/v1/pods":
			inventoryForbidden(w)
			return true
		case "/api/v1/namespaces/tenant-a":
			json.NewEncoder(w).Encode(corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"},
			})
			return true
		case "/api/v1/namespaces/tenant-a/pods":
			json.NewEncoder(w).Encode(corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "visible", Namespace: "tenant-a"},
			}}})
			return true
		}
		return false
	})
	inv, err := BuildInventory(context.Background(), sess, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Pods) != 1 || inv.Pods[0].Namespace != "tenant-a" {
		t.Fatalf("namespace-scoped pods were lost: %+v", inv.Pods)
	}
}

func TestInventoryPaginatesPods(t *testing.T) {
	pages := 0
	sess := inventoryTestSession(t, "tenant-a", func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/v1/namespaces/tenant-a/pods" {
			return false
		}
		pages++
		list := corev1.PodList{}
		switch r.URL.Query().Get("continue") {
		case "":
			list.Items = []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "tenant-a"}}}
			list.Continue = "page-two"
		case "page-two":
			list.Items = []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "tenant-a"}}}
		default:
			t.Errorf("unexpected continue token: %q", r.URL.Query().Get("continue"))
		}
		json.NewEncoder(w).Encode(list)
		return true
	})
	inv, err := BuildInventory(context.Background(), sess, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Pods) != 2 || pages != 2 {
		t.Fatalf("pods = %d, pages = %d, want 2 of each", len(inv.Pods), pages)
	}
}

func TestInventoryGetsExplicitNamespaceWithoutListPermission(t *testing.T) {
	sess := inventoryTestSession(t, "tenant-a", func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/namespaces":
			inventoryForbidden(w)
			return true
		case "/api/v1/namespaces/tenant-a":
			json.NewEncoder(w).Encode(corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "tenant-a",
					Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"},
				},
			})
			return true
		}
		return false
	})
	inv, err := BuildInventory(context.Background(), sess, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Namespaces) != 1 || inv.Namespaces[0].Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		t.Fatalf("namespace admission labels were not collected: %+v", inv.Namespaces)
	}
}
