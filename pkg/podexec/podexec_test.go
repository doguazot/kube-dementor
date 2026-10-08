package podexec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func newWebhookCluster(t *testing.T) (*kubectx.Session, *[]string, func()) {
	t.Helper()
	var mu sync.Mutex
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure",`+
			`"message":"admission webhook \"deny-pod-exec.k8s.io\" denied the request: use the audited rexec plugin",`+
			`"reason":"Forbidden","code":403}`)
	}))
	cfg := &rest.Config{Host: server.URL}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	sess := &kubectx.Session{Client: client, RestCfg: cfg}
	return sess, &requests, server.Close
}

func installPlugin(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl-rexec")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return path
}

func withoutFixedPluginPaths(t *testing.T) {
	t.Helper()
	saved := fixedPluginPaths
	fixedPluginPaths = nil
	t.Cleanup(func() { fixedPluginPaths = saved })
}

func TestRunFallsBackToRexecWhenExecIsDenied(t *testing.T) {
	withoutFixedPluginPaths(t)
	sess, requests, closeServer := newWebhookCluster(t)
	defer closeServer()
	installPlugin(t, "#!/bin/sh\necho \"uid=0(root)\"\nexit 0\n", 0o755)

	r := Run(context.Background(), sess, "team", "target", "app", "id")

	if r.Err != nil {
		t.Fatalf("rexec fallback failed: %v", r.Err)
	}
	if r.Via != ViaRexec {
		t.Fatalf("via = %q, want %q", r.Via, ViaRexec)
	}
	if !strings.Contains(r.Output, "uid=0(root)") {
		t.Fatalf("output lost the command evidence: %q", r.Output)
	}
	for _, req := range *requests {
		if req != http.MethodPost+" /api/v1/namespaces/team/pods/target/exec" {
			t.Fatalf("unexpected apiserver request: %s", req)
		}
	}
}

func TestRunPreservesOutputWhenCommandExitsNonZero(t *testing.T) {
	withoutFixedPluginPaths(t)
	sess, _, closeServer := newWebhookCluster(t)
	defer closeServer()

	installPlugin(t, "#!/bin/sh\necho \"uid=0(root)\"\necho \"sh: hostname: not found\" 1>&2\nexit 127\n", 0o755)

	r := Run(context.Background(), sess, "team", "target", "app", "id; hostname")

	var exitErr *ExitError
	if !errors.As(r.Err, &exitErr) || exitErr.Code != 127 {
		t.Fatalf("err = %v, want ExitError{127}", r.Err)
	}
	if !strings.Contains(r.Output, "uid=0(root)") {
		t.Fatalf("non-zero exit discarded valid output: %q", r.Output)
	}
	if r.Via != ViaRexec {
		t.Fatalf("via = %q, want %q", r.Via, ViaRexec)
	}
}

func TestRunReportsOriginalErrorWithoutPlugin(t *testing.T) {
	withoutFixedPluginPaths(t)
	sess, _, closeServer := newWebhookCluster(t)
	defer closeServer()

	t.Setenv("PATH", t.TempDir())

	r := Run(context.Background(), sess, "team", "target", "app", "id")

	if r.Err == nil || !strings.Contains(r.Err.Error(), "admission webhook") {
		t.Fatalf("err = %v, want the original webhook denial", r.Err)
	}
	if r.Via != ViaExec {
		t.Fatalf("via = %q, want %q", r.Via, ViaExec)
	}
}

func TestRunReportsBothTransportsWhenBothFail(t *testing.T) {
	withoutFixedPluginPaths(t)
	sess, _, closeServer := newWebhookCluster(t)
	defer closeServer()

	installPlugin(t, "#!/nonexistent/interpreter\ntrue\n", 0o755)

	r := Run(context.Background(), sess, "team", "target", "app", "id")

	if r.Err == nil {
		t.Fatal("both transports failed but the error was swallowed")
	}
	msg := r.Err.Error()
	if !strings.Contains(msg, "pods/exec") || !strings.Contains(msg, "kubectl-rexec") {
		t.Fatalf("error hides one of the two attempts: %v", r.Err)
	}
}
