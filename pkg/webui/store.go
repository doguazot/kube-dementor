package webui

import (
	"sort"
	"sync"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type scanListEntry struct {
	ID       string               `json:"id"`
	Status   string               `json:"status"`
	Started  time.Time            `json:"started"`
	Finished time.Time            `json:"finished,omitempty"`
	Request  newScanReq           `json:"request"`
	Cluster  string               `json:"cluster,omitempty"`
	Summary  *scanner.ScanSummary `json:"summary,omitempty"`
}

type storeEntry struct {
	req       newScanReq
	report    *scanner.ScanReport
	started   time.Time
	exclusion []byte
}

type Store struct {
	mu   sync.RWMutex
	data map[string]*storeEntry
}

func NewStore() *Store {
	return &Store{data: make(map[string]*storeEntry)}
}

func (s *Store) Save(id string, req newScanReq, report *scanner.ScanReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = &storeEntry{
		req:     req,
		report:  report,
		started: report.Metadata.StartedAt,
	}
}

func (s *Store) Get(id string) (*scanner.ScanReport, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.data[id]; ok {
		return e.report, true
	}
	return nil, false
}

func (s *Store) GetRequest(id string) (newScanReq, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.data[id]; ok {
		return e.req, true
	}
	return newScanReq{}, false
}

func (s *Store) AppendLiveExploit(id string, entry scanner.LiveExploitEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[id]; ok && e.report != nil {
		e.report.Metadata.LiveExploits = append(e.report.Metadata.LiveExploits, entry)
	}
}

func (s *Store) SaveExclusion(id string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[id]; ok {
		e.exclusion = data
	}
}

func (s *Store) GetExclusion(id string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.data[id]; ok {
		return e.exclusion
	}
	return nil
}

func (s *Store) List() []scanListEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]scanListEntry, 0, len(s.data))
	for id, e := range s.data {
		sum := e.report.Summary
		out = append(out, scanListEntry{
			ID:       id,
			Status:   "completed",
			Started:  e.report.Metadata.StartedAt,
			Finished: e.report.Metadata.FinishedAt,
			Request:  e.req,
			Cluster:  e.report.Metadata.ClusterName,
			Summary:  &sum,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Started.After(out[j].Started)
	})
	return out
}
