package webui

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func (s *Server) handleCSV(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.repMu.RLock()
	rep, ok := s.store.Get(id)
	if !ok {
		s.repMu.RUnlock()
		writeError(w, 404, fmt.Errorf("scan %s not found", id))
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="kube-dementor-%s-%s.csv"`, safeFilename(rep.Metadata.ClusterName), id))

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"FindingID", "RuleID", "Severity", "Category",
		"Namespace", "ResourceKind", "ResourceName",
		"Title", "Description",
		"Evidence", "Impact", "Recommendation",
		"MitreATTACK",
		"ExploitAttempted", "ExploitVerified", "ExploitExploited",
		"ExploitSafetyLevel", "ExploitEvidence", "ExploitError",
		"Tags", "DetectedAt",
		"Accepted", "AcceptedBy", "AcceptedReason", "AcceptedScope",
	})
	for _, f := range rep.Findings {
		_ = cw.Write(findingCSVRow(f, findAcceptance(rep, f.ID)))
	}
	for _, f := range rep.AcceptedFindings {
		_ = cw.Write(findingCSVRow(f, findAcceptance(rep, f.ID)))
	}
	s.repMu.RUnlock()
}

func findingCSVRow(f scanner.Finding, acceptance *scanner.Acceptance) []string {
	expAtt, expVer, expExp, expLvl, expEv, expErr := "", "", "", "", "", ""
	if f.Exploit != nil {
		expAtt = fmt.Sprintf("%t", f.Exploit.Attempted)
		expVer = fmt.Sprintf("%t", f.Exploit.Verified)
		expExp = fmt.Sprintf("%t", f.Exploit.Exploited)
		expLvl = f.Exploit.SafetyLevel
		expEv = collapseLines(f.Exploit.Evidence)
		expErr = collapseLines(f.Exploit.Error)
	}
	accepted, acceptedBy, acceptedReason, acceptedScope := "false", "", "", ""
	if acceptance != nil {
		accepted = "true"
		acceptedBy = acceptance.By
		acceptedReason = acceptance.Reason
		acceptedScope = acceptance.Scope
	} else if f.Accepted {
		accepted = "true"
		acceptedBy = f.AcceptedBy
		acceptedReason = f.AcceptedReason
		acceptedScope = f.AcceptedScope
	}
	return []string{
		csvCell(f.ID), csvCell(f.RuleID), csvCell(string(f.Severity)), csvCell(string(f.Category)),
		csvCell(f.Resource.Namespace), csvCell(f.Resource.Kind), csvCell(f.Resource.Name),
		csvCell(collapseLines(f.Title)), csvCell(collapseLines(f.Description)),
		csvCell(collapseLines(f.Evidence)), csvCell(collapseLines(f.Impact)), csvCell(collapseLines(f.Recommendation)),
		csvCell(strings.Join(f.MitreATTACK, ";")),
		expAtt, expVer, expExp, csvCell(expLvl), csvCell(expEv), csvCell(expErr),
		csvCell(strings.Join(f.Tags, ";")),
		f.DetectedAt.Format("2006-01-02T15:04:05Z"),
		accepted, csvCell(acceptedBy), csvCell(acceptedReason), csvCell(acceptedScope),
	}
}

func csvCell(s string) string {
	if s == "" {
		return ""
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func collapseLines(s string) string {
	r := strings.NewReplacer("\n", " / ", "\r", "", "\t", " ")
	return r.Replace(s)
}

func safeFilename(s string) string {
	r := strings.NewReplacer("/", "_", " ", "_", ":", "_")
	return r.Replace(s)
}

func findAcceptance(rep *scanner.ScanReport, findingID string) *scanner.Acceptance {
	for i := range rep.Metadata.Acceptances {
		if rep.Metadata.Acceptances[i].FindingID == findingID {
			return &rep.Metadata.Acceptances[i]
		}
	}
	return nil
}
