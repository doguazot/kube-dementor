package reporter

import (
	"encoding/csv"
	"io"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func WriteCSV(w io.Writer, rep *scanner.ScanReport) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	header := []string{
		"FindingID", "RuleID", "Severity", "Category",
		"Namespace", "ResourceKind", "ResourceName",
		"Title", "Description", "Evidence", "Impact", "Recommendation",
		"MitreATTACK",
		"ExploitAttempted", "ExploitVerified", "ExploitExploited",
		"ExploitSafetyLevel", "ExploitEvidence", "ExploitError",
		"Accepted", "AcceptedBy", "AcceptedReason", "AcceptedScope",
		"Tags", "DetectedAt",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, f := range rep.Findings {
		if err := cw.Write(rowFor(f)); err != nil {
			return err
		}
	}
	for _, f := range rep.AcceptedFindings {
		if err := cw.Write(rowFor(f)); err != nil {
			return err
		}
	}
	return nil
}

func rowFor(f scanner.Finding) []string {
	expAtt, expVer, expExp, expLvl, expEv, expErr := "", "", "", "", "", ""
	if f.Exploit != nil {
		expAtt = csvBool(f.Exploit.Attempted)
		expVer = csvBool(f.Exploit.Verified)
		expExp = csvBool(f.Exploit.Exploited)
		expLvl = f.Exploit.SafetyLevel
		expEv = flatCSV(f.Exploit.Evidence)
		expErr = flatCSV(f.Exploit.Error)
	}
	return []string{
		csvCell(f.ID), csvCell(f.RuleID), csvCell(string(f.Severity)), csvCell(string(f.Category)),
		csvCell(f.Resource.Namespace), csvCell(f.Resource.Kind), csvCell(f.Resource.Name),
		csvCell(flatCSV(f.Title)), csvCell(flatCSV(f.Description)),
		csvCell(flatCSV(f.Evidence)), csvCell(flatCSV(f.Impact)), csvCell(flatCSV(f.Recommendation)),
		csvCell(strings.Join(f.MitreATTACK, ";")),
		expAtt, expVer, expExp, csvCell(expLvl), csvCell(expEv), csvCell(expErr),
		csvBool(f.Accepted), csvCell(f.AcceptedBy), csvCell(flatCSV(f.AcceptedReason)), csvCell(f.AcceptedScope),
		csvCell(strings.Join(f.Tags, ";")),
		f.DetectedAt.Format("2006-01-02T15:04:05Z"),
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

func flatCSV(s string) string {
	r := strings.NewReplacer("\n", " / ", "\r", "", "\t", " ")
	return r.Replace(s)
}

func csvBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
