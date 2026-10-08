package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func TestInvalidRelationshipAndUnconfiguredRawQueriesAreRejected(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	server.handleAttackPaths(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/attack-paths?type=INVALID%5D", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid type returned %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	server.handleCustomQuery(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/query",
		strings.NewReader(`{"cypher":"MATCH (n) DETACH DELETE n"}`)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unconfigured raw query returned %d", recorder.Code)
	}
}

func TestConcurrentLegacyGraphScansAreRejected(t *testing.T) {
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := &Server{runScan: func(string, string) {
		close(started)
		<-release
		close(finished)
	}}
	first := httptest.NewRecorder()
	server.handleNewScan(first, httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{}`)))
	<-started
	second := httptest.NewRecorder()
	server.handleNewScan(second, httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{}`)))
	close(release)
	<-finished
	if first.Code != http.StatusAccepted || second.Code != http.StatusConflict {
		t.Fatalf("scan statuses=%d,%d, want 202,409", first.Code, second.Code)
	}
}

type fakeReadResult struct {
	neo4j.ResultWithContext
	err error
}

func (result *fakeReadResult) Next(context.Context) bool { return false }
func (result *fakeReadResult) Err() error                { return result.err }

type fakeReadSession struct {
	neo4j.SessionWithContext
	queries []string
	err     error
}

func (session *fakeReadSession) Run(_ context.Context, query string, _ map[string]any, _ ...func(*neo4j.TransactionConfig)) (neo4j.ResultWithContext, error) {
	session.queries = append(session.queries, query)
	return &fakeReadResult{err: session.err}, nil
}
func (session *fakeReadSession) Close(context.Context) error { return nil }

type fakeReadDriver struct {
	neo4j.DriverWithContext
	session *fakeReadSession
}

func (driver *fakeReadDriver) NewSession(context.Context, neo4j.SessionConfig) neo4j.SessionWithContext {
	return driver.session
}

func TestReadStreamFailureIsNotReportedAsNoPaths(t *testing.T) {
	session := &fakeReadSession{err: errors.New("synthetic read-stream failure")}
	server := &Server{driver: &fakeReadDriver{session: session}}
	recorder := httptest.NewRecorder()
	server.handleShortestPath(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/shortest-path?target=cluster-admin", nil))
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), "no paths found") {
		t.Fatalf("read-stream error became clean result: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAttackChainIncludesContainerTraversalAndDirectPermissions(t *testing.T) {
	session := &fakeReadSession{}
	server := &Server{driver: &fakeReadDriver{session: session}}
	recorder := httptest.NewRecorder()
	server.handleAttackChain(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/attack-chain?identity=alice", nil))
	if recorder.Code != http.StatusOK || len(session.queries) != 2 {
		t.Fatalf("attack chain failed: %d %v", recorder.Code, session.queries)
	}
	if !strings.Contains(session.queries[0], "CONTAINS") || !strings.Contains(session.queries[0], "*1..6") ||
		strings.Contains(session.queries[0], "HAS_PERMISSION") || !strings.Contains(session.queries[1], "HAS_PERMISSION") {
		t.Fatalf("attack and permission traversal contracts are incorrect: %v", session.queries)
	}
}

func TestDashboardReadsWorkWithCustomQueriesDisabled(t *testing.T) {
	session := &fakeReadSession{}
	server := &Server{driver: &fakeReadDriver{session: session}}
	for _, tc := range []struct {
		url     string
		handler http.HandlerFunc
	}{
		{"/api/v1/graph", server.handleGraph},
		{"/api/v1/exploitability-details?status=UNCHECKED", server.handleExploitabilityDetails},
	} {
		recorder := httptest.NewRecorder()
		tc.handler(recorder, httptest.NewRequest(http.MethodGet, tc.url, nil))
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "[]" {
			t.Fatalf("fixed dashboard read requires raw queries: %d %s", recorder.Code, recorder.Body.String())
		}
	}
	if !strings.Contains(session.queries[0], "CASE WHEN type(rel)") || !strings.Contains(session.queries[1], "$status") {
		t.Fatalf("dashboard query is unbounded, unordered, or unparameterized: %v", session.queries)
	}
	session.err = errors.New("synthetic graph read failure")
	recorder := httptest.NewRecorder()
	server.handleGraph(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/graph", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("graph read failure became empty result: %d", recorder.Code)
	}
}
