package scanstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ScanMeta struct {
	ID          string    `json:"id"`
	StartedAt   time.Time `json:"startedAt"`
	FinishedAt  time.Time `json:"finishedAt"`
	Namespace   string    `json:"namespace"`
	Kubeconfig  string    `json:"kubeconfig"`
	ClusterName string    `json:"clusterName"`
	NodeCount   int       `json:"nodeCount"`
	EdgeCount   int       `json:"edgeCount"`
	Exploitable int       `json:"exploitable"`
	NotExploit  int       `json:"notExploitable"`
	Unchecked   int       `json:"unchecked,omitempty"`
	Status      string    `json:"status"`
	Error       string    `json:"error,omitempty"`
	Incomplete  bool      `json:"incomplete,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
}

type ScanEdge struct {
	SourceName string            `json:"sourceName"`
	TargetName string            `json:"targetName"`
	Type       string            `json:"type"`
	Properties map[string]string `json:"properties,omitempty"`
}

type ScanNodeSummary struct {
	Identities     int `json:"identities"`
	Pods           int `json:"pods"`
	Containers     int `json:"containers"`
	Nodes          int `json:"nodes"`
	Volumes        int `json:"volumes"`
	PermissionSets int `json:"permissionSets"`
	Actions        int `json:"actions"`
}

type ScanResults struct {
	Meta  ScanMeta        `json:"meta"`
	Nodes ScanNodeSummary `json:"nodes"`
	Edges []ScanEdge      `json:"edges"`
}

type Store struct {
	dir string
	mu  sync.RWMutex
}

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create scan store dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Save(meta *ScanMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, meta.ID+".json")
	return os.WriteFile(path, data, 0644)
}

func (s *Store) Get(id string) (*ScanMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta ScanMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func (s *Store) SaveResults(id string, results *ScanResults) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(results)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, id+"-results.json")
	return os.WriteFile(path, data, 0644)
}

func (s *Store) GetResults(id string) (*ScanResults, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.dir, id+"-results.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var results ScanResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	return &results, nil
}

func (s *Store) List() ([]ScanMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var scans []ScanMeta
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" || strings.HasSuffix(e.Name(), "-results.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var meta ScanMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		scans = append(scans, meta)
	}

	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartedAt.After(scans[j].StartedAt)
	})
	return scans, nil
}
