package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestShellStatusShowsDisabledModeWithoutAnyClusterRequest(t *testing.T) {
	server := NewServer("")
	for _, handler := range []http.HandlerFunc{server.handleShellStatus, server.handleShell} {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodGet, "/shell?confirm=fixture", nil))
		if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "shells are disabled") {
			t.Fatalf("real shell rejection was hidden: %d %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestShellPreflightOnlyReadsTheTargetAndKeepsGuardLocked(t *testing.T) {
	var reads atomic.Int32
	cluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/team/pods/target" {
			t.Errorf("preflight invoked mutation or exec: %s %s", r.Method, r.URL)
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(corev1.Pod{
			TypeMeta:   metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "team"},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
				Name: "app", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}}},
		})
	}))
	defer cluster.Close()
	cfg := &rest.Config{Host: cluster.URL}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	session, guard, err := kubectx.WrapSessionReadOnly(&kubectx.Session{RestCfg: cfg, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer("")
	server.AllowLiveExploit = true
	server.sessions["scan"] = session
	server.store.Save("scan", newScanReq{}, &scanner.ScanReport{
		Metadata: scanner.ScanMetadata{ClusterName: "fixture"},
		Findings: []scanner.Finding{{
			ID: "finding", RuleID: "KH-CHAIN-SHELL",
			Resource: scanner.Resource{Kind: "Pod", Namespace: "team", Name: "target"},
			Shell:    &scanner.ShellTarget{Verified: true, Container: "app", Scope: "container"},
			Exploit:  &scanner.ExploitResult{Verified: true},
		}},
	})
	request := httptest.NewRequest(http.MethodGet, "/shell-status?confirm=fixture", nil)
	request.SetPathValue("id", "scan")
	request.SetPathValue("fid", "finding")
	recorder := httptest.NewRecorder()
	server.handleShellStatus(recorder, request)
	if recorder.Code != http.StatusOK || reads.Load() != 1 || guard.AllowLiveExec {
		t.Fatalf("preflight status=%d reads=%d guardUnlocked=%t", recorder.Code, reads.Load(), guard.AllowLiveExec)
	}
}
