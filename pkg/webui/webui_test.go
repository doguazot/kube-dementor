package webui

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
)

type allowAllTransport struct{}

func (allowAllTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Header:     make(http.Header),
	}, nil
}

func TestConfigureChainGuardAlwaysDisablesDelete(t *testing.T) {
	guard := kubectx.NewReadOnlyGuard(allowAllTransport{})
	guard.AllowPodDelete = true
	guard.AllowSidecarPatch = true

	configureChainGuard(guard)

	deleteReq, err := http.NewRequest(
		http.MethodDelete,
		"https://cluster.test/api/v1/namespaces/tenant-a/pods/existing",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(deleteReq); err == nil {
		t.Fatal("chain guard allowed DELETE")
	}

	createReq, err := http.NewRequest(
		http.MethodPost,
		"https://cluster.test/api/v1/namespaces/tenant-a/pods",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(createReq); err != nil {
		t.Fatalf("chain guard blocked namespaced pod CREATE: %v", err)
	}
}

func TestConfigureChainGuardScopesEphemeralInjection(t *testing.T) {
	guard := kubectx.NewReadOnlyGuard(allowAllTransport{})
	configureChainGuard(guard)

	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		ephemeralReq, err := http.NewRequest(
			method,
			"https://cluster.test/api/v1/namespaces/tenant-a/pods/existing/ephemeralcontainers",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := guard.RoundTrip(ephemeralReq); err != nil {
			t.Fatalf("chain guard blocked %s on pods/ephemeralcontainers: %v", method, err)
		}
	}

	podSpecPatch, err := http.NewRequest(
		http.MethodPatch,
		"https://cluster.test/api/v1/namespaces/tenant-a/pods/existing",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(podSpecPatch); err == nil {
		t.Fatal("chain guard allowed a pod spec PATCH outside the ephemeralcontainers subresource")
	}

	deploymentPut, err := http.NewRequest(
		http.MethodPut,
		"https://cluster.test/apis/apps/v1/namespaces/tenant-a/deployments/existing",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RoundTrip(deploymentPut); err == nil {
		t.Fatal("chain guard allowed a deployment PUT")
	}
}
