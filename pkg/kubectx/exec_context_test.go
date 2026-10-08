package kubectx

import (
	"net/http"
	"testing"
)

func TestShellExecPermissionIsContextScopedAndNeverAllowsMutationOrTokens(t *testing.T) {
	guard := NewReadOnlyGuard(&recordingRoundTripper{})
	for _, path := range []string{
		"/api/v1/namespaces/team/pods/target/exec",
		"/api/v1/namespaces/team/pods",
		"/api/v1/namespaces/team/serviceaccounts/runner/token",
	} {
		request, err := http.NewRequest(http.MethodPost, "https://cluster.test"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		scoped := request.WithContext(WithPodExecPermission(request.Context()))
		_, err = guard.RoundTrip(scoped)
		if (err == nil) != (path == "/api/v1/namespaces/team/pods/target/exec") {
			t.Fatalf("scoped request unexpectedly allowed/denied %s: %v", path, err)
		}
		if _, err := guard.RoundTrip(request); err == nil {
			t.Fatalf("permission leaked to another request: %s", path)
		}
	}
}

func TestEphemeralContainerPatchIsNarrowAndRequiresChainOptIn(t *testing.T) {
	guard := NewReadOnlyGuard(&recordingRoundTripper{})
	target := "https://cluster.test/api/v1/namespaces/team/pods/target/ephemeralcontainers"

	off, err := http.NewRequest(http.MethodPut, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(off); err == nil {
		t.Fatal("ephemeral patch allowed without opt-in")
	}

	guard.AllowEphemeralPatch = true
	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		req, err := http.NewRequest(method, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.RoundTrip(req); err != nil {
			t.Fatalf("chain opt-in must allow %s ephemeralcontainers: %v", method, err)
		}
	}
	for _, rawURL := range []string{
		"https://cluster.test/api/v1/namespaces/team/pods/target",
		"https://cluster.test/api/v1/namespaces/team/pods/target/status",
		"https://cluster.test/api/v1/namespaces/team/pods/target/exec",
		"https://cluster.test/api/v1/namespaces/team/pods",
		"https://cluster.test/apis/apps/v1/namespaces/team/deployments/target/ephemeralcontainers",
	} {
		req, err := http.NewRequest(http.MethodPut, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.RoundTrip(req); err == nil {
			t.Fatalf("ephemeral opt-in leaked beyond the subresource: %s", rawURL)
		}
	}
	del, err := http.NewRequest(http.MethodDelete, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(del); err == nil {
		t.Fatal("DELETE must stay blocked even with ephemeral injection enabled")
	}
}
