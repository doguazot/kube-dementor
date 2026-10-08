package kubectx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"k8s.io/client-go/rest"
)

type recordingRoundTripper struct {
	mu    sync.Mutex
	calls int
}

func (r *recordingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Header:     make(http.Header),
	}, nil
}

func (r *recordingRoundTripper) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestReadOnlyGuardAllowsNarrowChainActions(t *testing.T) {
	base := &recordingRoundTripper{}
	guard := NewReadOnlyGuard(base)
	guard.AllowLiveExec = true
	guard.AllowPodCreate = true

	tests := []struct {
		name   string
		method string
		url    string
	}{
		{
			name:   "pod exec",
			method: http.MethodPost,
			url:    "https://cluster.test/api/v1/namespaces/tenant-a/pods/test/exec",
		},
		{
			name:   "service account token request",
			method: http.MethodPost,
			url:    "https://cluster.test/api/v1/namespaces/tenant-a/serviceaccounts/test/token",
		},
		{
			name:   "namespaced pod create",
			method: http.MethodPost,
			url:    "https://cluster.test/api/v1/namespaces/tenant-a/pods",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := guard.RoundTrip(req); err != nil {
				t.Fatalf("expected request to be allowed, got %v", err)
			}
		})
	}

	if got, want := base.callCount(), len(tests); got != want {
		t.Fatalf("base transport calls = %d, want %d", got, want)
	}
}

func TestReadOnlyGuardAlwaysBlocksDelete(t *testing.T) {
	base := &recordingRoundTripper{}
	guard := NewReadOnlyGuard(base)
	guard.AllowLiveExec = true
	guard.AllowPodCreate = true
	guard.AllowSidecarPatch = true

	for _, rawURL := range []string{
		"https://cluster.test/api/v1/namespaces/tenant-a/pods/existing",
		"https://cluster.test/api/v1/namespaces/tenant-a/pods/kd-chain-test?dryRun=All",
		"https://cluster.test/apis/apps/v1/namespaces/tenant-a/deployments/existing",
	} {
		req, err := http.NewRequest(http.MethodDelete, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.RoundTrip(req); err == nil {
			t.Fatalf("expected DELETE %s to be blocked", rawURL)
		} else if _, ok := err.(*ReadOnlyViolation); !ok {
			t.Fatalf("expected ReadOnlyViolation, got %T: %v", err, err)
		}
	}

	if got := base.callCount(); got != 0 {
		t.Fatalf("DELETE reached base transport %d time(s)", got)
	}
	if got := len(guard.Violations()); got != 3 {
		t.Fatalf("violations = %d, want 3", got)
	}
}

func TestReadOnlyGuardPodDeleteRequiresExplicitOptIn(t *testing.T) {
	base := &recordingRoundTripper{}
	guard := NewReadOnlyGuard(base)
	guard.AllowPodDelete = true

	allowed, err := http.NewRequest(
		http.MethodDelete,
		"https://cluster.test/api/v1/namespaces/tenant-a/pods/kd-chain-test",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(allowed); err != nil {
		t.Fatalf("expected exact pod DELETE to be allowed, got %v", err)
	}

	for _, rawURL := range []string{
		"https://cluster.test/api/v1/namespaces/tenant-a/pods",
		"https://cluster.test/api/v1/namespaces/tenant-a/pods/existing/status",
		"https://cluster.test/apis/apps/v1/namespaces/tenant-a/deployments/existing",
	} {
		req, err := http.NewRequest(http.MethodDelete, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.RoundTrip(req); err == nil {
			t.Fatalf("expected DELETE %s to be blocked", rawURL)
		}
	}

	if got, want := base.callCount(), 1; got != want {
		t.Fatalf("base transport calls = %d, want %d", got, want)
	}
}

func TestReadOnlyGuardDoesNotBroadenPodCreate(t *testing.T) {
	base := &recordingRoundTripper{}
	guard := NewReadOnlyGuard(base)
	guard.AllowPodCreate = true

	for _, rawURL := range []string{
		"https://cluster.test/api/v1/namespaces/tenant-a/pods/existing",
		"https://cluster.test/apis/apps/v1/namespaces/tenant-a/deployments",
		"https://cluster.test/api/v1/pods",
	} {
		req, err := http.NewRequest(http.MethodPost, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.RoundTrip(req); err == nil {
			t.Fatalf("expected POST %s to be blocked", rawURL)
		}
	}

	if got := base.callCount(); got != 0 {
		t.Fatalf("unexpected request reached base transport %d time(s)", got)
	}
}

func TestWrappedSessionSharesPolicyAcrossDerivedTransports(t *testing.T) {
	var mu sync.Mutex
	serverCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		serverCalls++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	session, guard, err := WrapSessionReadOnly(&Session{
		RestCfg: &rest.Config{Host: server.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	guard.AllowLiveExec = true
	guard.AllowPodCreate = true

	for i := 0; i < 2; i++ {
		transport, err := rest.TransportFor(session.RestCfg)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(
			http.MethodDelete,
			server.URL+"/api/v1/namespaces/tenant-a/pods/existing",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transport.RoundTrip(req); err == nil {
			t.Fatal("derived transport allowed DELETE")
		}
	}

	mu.Lock()
	gotServerCalls := serverCalls
	mu.Unlock()
	if gotServerCalls != 0 {
		t.Fatalf("DELETE reached server %d time(s)", gotServerCalls)
	}
	if got := len(guard.Violations()); got != 2 {
		t.Fatalf("shared guard violations = %d, want 2", got)
	}
}
