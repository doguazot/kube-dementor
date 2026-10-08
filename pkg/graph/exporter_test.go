package graph

import (
	"context"
	"errors"
	"testing"

	"github.com/kube-dementor/kube-dementor/pkg/models"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type deferredErrorResult struct {
	neo4j.ResultWithContext
	consumed bool
	err      error
}

func (result *deferredErrorResult) Consume(context.Context) (neo4j.ResultSummary, error) {
	result.consumed = true
	return nil, result.err
}

type fakeWriteSession struct {
	neo4j.SessionWithContext
	result *deferredErrorResult
	calls  int
}

func (session *fakeWriteSession) Run(context.Context, string, map[string]any, ...func(*neo4j.TransactionConfig)) (neo4j.ResultWithContext, error) {
	session.calls++
	return session.result, nil
}

func TestBatchWritePropagatesDeferredCommitError(t *testing.T) {
	want := errors.New("synthetic deferred commit failure")
	session := &fakeWriteSession{result: &deferredErrorResult{err: want}}
	err := batchWrite(context.Background(), session, "synthetic write", []string{"item"},
		func(item string) map[string]any { return map[string]any{"name": item} }, "fixture")
	if !errors.Is(err, want) || !session.result.consumed {
		t.Fatalf("deferred write failure was lost: %v consumed=%t", err, session.result.consumed)
	}
}

func TestExporterRejectsInvalidRelationshipBeforeWriting(t *testing.T) {
	session := &fakeWriteSession{result: &deferredErrorResult{}}
	err := New("", "", "", "").insertEdges(context.Background(), session, []models.Edge{{
		Type: models.EdgeType("INVALID] DELETE n //"),
	}})
	if err == nil || session.calls != 0 {
		t.Fatalf("invalid relationship reached database: error=%v calls=%d", err, session.calls)
	}
}
