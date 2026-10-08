package kubectx

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
)

type execPermissionKey struct{}

func WithPodExecPermission(ctx context.Context) context.Context {
	return context.WithValue(ctx, execPermissionKey{}, true)
}

type ReadOnlyViolation struct {
	Method string
	Path   string
	Query  string
}

func (e *ReadOnlyViolation) Error() string {
	return fmt.Sprintf("kube-dementor safety-guard: blocked %s %s?%s (mutations disabled)",
		e.Method, e.Path, e.Query)
}

type ReadOnlyGuard struct {
	base http.RoundTripper

	mu         sync.Mutex
	violations []ReadOnlyViolation

	AllowLiveExec bool

	AllowPodCreate bool

	AllowPodDelete bool

	AllowSidecarPatch bool

	AllowEphemeralPatch bool
}

type guardedRoundTripper struct {
	base  http.RoundTripper
	guard *ReadOnlyGuard
}

func NewReadOnlyGuard(base http.RoundTripper) *ReadOnlyGuard {
	return &ReadOnlyGuard{base: base}
}

func (g *ReadOnlyGuard) Violations() []ReadOnlyViolation {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ReadOnlyViolation, len(g.violations))
	copy(out, g.violations)
	return out
}

func (g *ReadOnlyGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	return g.roundTrip(g.base, req)
}

func (g *ReadOnlyGuard) roundTrip(base http.RoundTripper, req *http.Request) (*http.Response, error) {
	if g.isAllowed(req) {
		return base.RoundTrip(req)
	}
	v := ReadOnlyViolation{
		Method: req.Method,
		Path:   req.URL.Path,
		Query:  req.URL.RawQuery,
	}
	g.mu.Lock()
	g.violations = append(g.violations, v)
	g.mu.Unlock()
	return nil, &v
}

func (t *guardedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.guard.roundTrip(t.base, req)
}

func (g *ReadOnlyGuard) isAllowed(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	case http.MethodPost:
		p := req.URL.Path
		if allowed, _ := req.Context().Value(execPermissionKey{}).(bool); allowed &&
			strings.HasPrefix(p, "/api/v1/namespaces/") && strings.Contains(p, "/pods/") && strings.HasSuffix(p, "/exec") {
			return true
		}
		if strings.HasSuffix(p, "/selfsubjectaccessreviews") ||
			strings.HasSuffix(p, "/selfsubjectrulesreviews") ||
			strings.HasSuffix(p, "/selfsubjectreviews") ||
			strings.HasSuffix(p, "/subjectaccessreviews") ||
			strings.HasSuffix(p, "/localsubjectaccessreviews") ||
			strings.HasSuffix(p, "/tokenreviews") {
			return true
		}
		if hasDryRunAll(req) {
			return true
		}
		if g.AllowLiveExec {

			if (strings.HasSuffix(p, "/exec") || strings.HasSuffix(p, "/attach")) && strings.Contains(p, "/pods/") {
				return true
			}

			if strings.HasSuffix(p, "/token") && strings.Contains(p, "/serviceaccounts/") {
				return true
			}
		}
		if g.AllowPodCreate && isNamespacedPodCollectionPath(p) {
			return true
		}
	case http.MethodDelete:
		if g.AllowPodDelete && isNamespacedPodResourcePath(req.URL.Path) {
			return true
		}
	case http.MethodPut, http.MethodPatch:
		if hasDryRunAll(req) {
			return true
		}
		if g.AllowEphemeralPatch && isNamespacedPodEphemeralContainersPath(req.URL.Path) {
			return true
		}
		if g.AllowSidecarPatch && req.Method == http.MethodPatch {
			p := req.URL.Path
			if strings.Contains(p, "/pods/") || strings.Contains(p, "/deployments/") {
				return true
			}
		}
	}
	return false
}

func isNamespacedPodCollectionPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 5 &&
		parts[0] == "api" &&
		parts[1] == "v1" &&
		parts[2] == "namespaces" &&
		parts[3] != "" &&
		parts[4] == "pods"
}

func isNamespacedPodResourcePath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 6 &&
		parts[0] == "api" &&
		parts[1] == "v1" &&
		parts[2] == "namespaces" &&
		parts[3] != "" &&
		parts[4] == "pods" &&
		parts[5] != ""
}

func isNamespacedPodEphemeralContainersPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 7 &&
		parts[0] == "api" &&
		parts[1] == "v1" &&
		parts[2] == "namespaces" &&
		parts[3] != "" &&
		parts[4] == "pods" &&
		parts[5] != "" &&
		parts[6] == "ephemeralcontainers"
}

func hasDryRunAll(req *http.Request) bool {
	q := req.URL.Query()
	for _, v := range q["dryRun"] {
		if v == "All" {
			return true
		}
	}
	return false
}

func WrapSessionReadOnly(s *Session) (*Session, *ReadOnlyGuard, error) {
	if s == nil || s.RestCfg == nil {
		return nil, nil, fmt.Errorf("nil session")
	}
	cfg := rest.CopyConfig(s.RestCfg)

	guard := NewReadOnlyGuard(nil)
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &guardedRoundTripper{base: rt, guard: guard}
	})

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap client: %w", err)
	}

	newSess := &Session{
		Info:      s.Info,
		RestCfg:   cfg,
		Client:    cs,
		Discovery: cs.Discovery(),
	}
	return newSess, guard, nil
}

var _ http.RoundTripper = (*ReadOnlyGuard)(nil)
var _ http.RoundTripper = (*guardedRoundTripper)(nil)
var _ transport.WrapperFunc = func(rt http.RoundTripper) http.RoundTripper {
	return &guardedRoundTripper{base: rt, guard: NewReadOnlyGuard(nil)}
}

func MustDiscovery(s *Session) discovery.DiscoveryInterface {
	if s == nil {
		return nil
	}
	return s.Discovery
}
