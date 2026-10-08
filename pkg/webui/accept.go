package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/policy"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type acceptReq struct {
	FindingID string `json:"findingId"`
	Reason    string `json:"reason"`
	By        string `json:"by"`
	Global    bool   `json:"global"`
}

func (s *Server) handleAccept(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body acceptReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAcceptBodyBytes)).Decode(&body); err != nil {
		writeBodyError(w, err, maxAcceptBodyBytes)
		return
	}
	s.repMu.Lock()
	rep, ok := s.store.Get(id)
	if !ok {
		s.repMu.Unlock()
		writeError(w, 404, fmt.Errorf("scan %s not found", id))
		return
	}
	if body.By == "" {
		body.By = "local"
	}
	moved, found := moveFindingToAccepted(rep, body.FindingID, body.Reason, body.By, "scan")
	if !found {
		s.repMu.Unlock()
		writeError(w, 404, fmt.Errorf("finding %s not in active list", body.FindingID))
		return
	}
	rep.Summary = scanner.ComputeSummary(rep.Findings)
	rep.Summary.Accepted = len(rep.AcceptedFindings)
	rep.Metadata.Acceptances = append(rep.Metadata.Acceptances, scanner.Acceptance{
		FindingID: moved.ID, RuleID: moved.RuleID, Signature: moved.Signature,
		By: body.By, Reason: body.Reason, At: time.Now(), Scope: "scan",
	})
	req, _ := s.store.GetRequest(id)
	s.persistReport(id, req, rep)
	summary := rep.Summary
	s.repMu.Unlock()

	var globalError string
	if body.Global && moved.Signature != "" {
		if err := policy.AddGlobalAccept(scanner.GlobalAcceptance{
			Signature: moved.Signature, RuleID: moved.RuleID, Title: moved.Title,
			Namespace: moved.Resource.Namespace, Resource: moved.Resource.String(),
			By: body.By, Reason: body.Reason, At: time.Now(),
		}); err != nil {
			globalError = err.Error()
		}
	}
	resp := map[string]any{
		"ok":          true,
		"finding":     moved,
		"globalAdded": body.Global,
		"summary":     summary,
	}
	if globalError != "" {
		resp["globalError"] = globalError
	}
	writeJSON(w, 200, resp)
}

func (s *Server) handleUnaccept(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body acceptReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAcceptBodyBytes)).Decode(&body); err != nil {
		writeBodyError(w, err, maxAcceptBodyBytes)
		return
	}
	s.repMu.Lock()
	rep, ok := s.store.Get(id)
	if !ok {
		s.repMu.Unlock()
		writeError(w, 404, fmt.Errorf("scan %s not found", id))
		return
	}
	moved := moveFindingBack(rep, body.FindingID)
	if moved == nil {
		s.repMu.Unlock()
		writeError(w, 404, fmt.Errorf("finding %s not accepted", body.FindingID))
		return
	}

	out := rep.Metadata.Acceptances[:0]
	for _, a := range rep.Metadata.Acceptances {
		if a.FindingID != moved.ID {
			out = append(out, a)
		}
	}
	rep.Metadata.Acceptances = out
	rep.Summary = scanner.ComputeSummary(rep.Findings)
	rep.Summary.Accepted = len(rep.AcceptedFindings)
	req, _ := s.store.GetRequest(id)
	s.persistReport(id, req, rep)
	summary := rep.Summary
	s.repMu.Unlock()

	if body.Global && moved.Signature != "" {
		if err := policy.RemoveGlobalAccept(moved.Signature); err != nil {
			log.Printf("[webui] remove global accept %s: %v", moved.Signature, err)
		}
	}
	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"finding": moved,
		"summary": summary,
	})
}

func (s *Server) handleGlobalAcceptedList(w http.ResponseWriter, r *http.Request) {
	list, err := policy.LoadGlobalAccepts()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"path":  policy.DefaultGlobalAcceptPath(),
		"items": list,
	})
}

func (s *Server) handleGlobalAccept(w http.ResponseWriter, r *http.Request) {
	var e scanner.GlobalAcceptance
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAcceptBodyBytes)).Decode(&e); err != nil {
		writeBodyError(w, err, maxAcceptBodyBytes)
		return
	}
	if e.Signature == "" {
		writeError(w, 400, fmt.Errorf("signature required"))
		return
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	if err := policy.AddGlobalAccept(e); err != nil {
		writeError(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "signature": e.Signature})
}

func (s *Server) handleGlobalUnaccept(w http.ResponseWriter, r *http.Request) {
	sig := r.PathValue("sig")
	if err := policy.RemoveGlobalAccept(sig); err != nil {
		writeError(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "removed": sig})
}

func (s *Server) handleUploadExclusions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.repMu.RLock()
	_, ok := s.store.Get(id)
	s.repMu.RUnlock()
	if !ok {
		writeError(w, 404, fmt.Errorf("scan %s not found", id))
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxExclusionBytes))
	if err != nil {
		writeError(w, 413, fmt.Errorf("exclusion payload too large (max %d bytes)", maxExclusionBytes))
		return
	}
	set, err := policy.ParseExclusions(data)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	s.repMu.Lock()
	rep, ok := s.store.Get(id)
	if !ok {
		s.repMu.Unlock()
		writeError(w, 404, fmt.Errorf("scan %s not found", id))
		return
	}

	active, suppressed, rulesHit := set.Apply(rep.Findings)
	rep.Findings = active
	rep.AcceptedFindings = append(rep.AcceptedFindings, suppressed...)
	if len(rulesHit) > 0 {
		seen := map[string]bool{}
		for _, v := range rep.Metadata.ExclusionsApplied {
			seen[v] = true
		}
		for _, v := range rulesHit {
			if !seen[v] {
				rep.Metadata.ExclusionsApplied = append(rep.Metadata.ExclusionsApplied, v)
			}
		}
	}

	s.store.SaveExclusion(id, data)
	rep.Summary = scanner.ComputeSummary(rep.Findings)
	rep.Summary.Accepted = len(rep.AcceptedFindings)
	req, _ := s.store.GetRequest(id)
	s.persistReport(id, req, rep)
	summary := rep.Summary
	activeCount := len(rep.Findings)
	s.repMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"ok":             true,
		"rulesParsed":    len(set.Entries),
		"newlyAccepted":  len(suppressed),
		"rulesHit":       rulesHit,
		"activeFindings": activeCount,
		"summary":        summary,
	})
}

func (s *Server) handleGetExclusions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	data := s.store.GetExclusion(id)
	if len(data) == 0 {
		writeError(w, 404, fmt.Errorf("no exclusion file stored for scan %s", id))
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="kube-dementor-exclusions.yaml"`)
	_, _ = w.Write(data)
}

func moveFindingToAccepted(rep *scanner.ScanReport, findingID, reason, by, scope string) (scanner.Finding, bool) {
	for i, f := range rep.Findings {
		if f.ID == findingID {
			f.Accepted = true
			f.AcceptedReason = reason
			f.AcceptedBy = by
			f.AcceptedScope = scope
			rep.Findings = append(rep.Findings[:i], rep.Findings[i+1:]...)
			rep.AcceptedFindings = append(rep.AcceptedFindings, f)
			return f, true
		}
	}
	return scanner.Finding{}, false
}

func moveFindingBack(rep *scanner.ScanReport, findingID string) *scanner.Finding {
	for i, f := range rep.AcceptedFindings {
		if f.ID == findingID {
			f.Accepted = false
			f.AcceptedReason = ""
			f.AcceptedBy = ""
			f.AcceptedScope = ""
			rep.AcceptedFindings = append(rep.AcceptedFindings[:i], rep.AcceptedFindings[i+1:]...)
			rep.Findings = append(rep.Findings, f)
			scanner.SortFindings(rep.Findings)
			return &f
		}
	}
	return nil
}
