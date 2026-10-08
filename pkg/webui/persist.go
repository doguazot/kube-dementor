package webui

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

const persistedReportFormat = 2

type persistedReport struct {
	Format  int                 `json:"format"`
	ID      string              `json:"id"`
	SavedAt time.Time           `json:"savedAt"`
	Request newScanReq          `json:"request"`
	Report  *scanner.ScanReport `json:"report"`
}

func reportsDir() string {
	if dir := os.Getenv("KUBE_DEMENTOR_REPORTS_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".kube-dementor", "reports")
}

func (s *Server) persistReport(id string, req newScanReq, report *scanner.ScanReport) {
	dir := reportsDir()
	if dir == "" || report == nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("[webui] persist report %s: %v", id, err)
		return
	}
	data, err := json.MarshalIndent(persistedReport{
		Format:  persistedReportFormat,
		ID:      id,
		SavedAt: time.Now(),
		Request: req,
		Report:  report,
	}, "", "  ")
	if err != nil {
		log.Printf("[webui] persist report %s: %v", id, err)
		return
	}
	path := filepath.Join(dir, sanitizeFileID(id)+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("[webui] persist report %s: %v", id, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[webui] persist report %s: %v", id, err)
	}
	if excl := s.store.GetExclusion(id); len(excl) > 0 {
		_ = os.WriteFile(filepath.Join(dir, sanitizeFileID(id)+".exclusions.yaml"), excl, 0o600)
	}
}

func (s *Server) loadPersistedReports() {
	dir := reportsDir()
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[webui] load persisted reports: %v", err)
		}
		return
	}
	loaded := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			log.Printf("[webui] skip %s: %v", name, err)
			continue
		}
		var pr persistedReport
		if err := json.Unmarshal(data, &pr); err != nil {
			log.Printf("[webui] skip corrupt report %s: %v", name, err)
			continue
		}
		if pr.Format != persistedReportFormat || pr.ID == "" || pr.Report == nil {
			log.Printf("[webui] skip incompatible report %s", name)
			continue
		}
		s.store.Save(pr.ID, pr.Request, pr.Report)
		if excl, err := os.ReadFile(filepath.Join(dir, strings.TrimSuffix(name, ".json")+".exclusions.yaml")); err == nil {
			s.store.SaveExclusion(pr.ID, excl)
		}
		loaded++
	}
	if loaded > 0 {
		log.Printf("[webui] restored %d persisted report(s) from %s", loaded, dir)
	}
}

func sanitizeFileID(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, id)
}
