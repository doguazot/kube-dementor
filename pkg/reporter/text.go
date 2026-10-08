package reporter

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

const (
	cReset   = "\033[0m"
	cBold    = "\033[1m"
	cDim     = "\033[2m"
	cRed     = "\033[31m"
	cGreen   = "\033[32m"
	cYellow  = "\033[33m"
	cBlue    = "\033[34m"
	cMagenta = "\033[35m"
	cCyan    = "\033[36m"
	cGray    = "\033[90m"
)

type theme struct{ enabled bool }

func (t theme) c(code, s string) string {
	if !t.enabled {
		return s
	}
	return code + s + cReset
}

func (t theme) bold(s string) string    { return t.c(cBold, s) }
func (t theme) dim(s string) string     { return t.c(cDim, s) }
func (t theme) red(s string) string     { return t.c(cRed, s) }
func (t theme) green(s string) string   { return t.c(cGreen, s) }
func (t theme) yellow(s string) string  { return t.c(cYellow, s) }
func (t theme) blue(s string) string    { return t.c(cBlue, s) }
func (t theme) magenta(s string) string { return t.c(cMagenta, s) }
func (t theme) cyan(s string) string    { return t.c(cCyan, s) }
func (t theme) gray(s string) string    { return t.c(cGray, s) }

func sevColor(t theme, s scanner.Severity) string {
	switch s {
	case scanner.SevCritical:
		return t.c(cBold+cRed, string(s))
	case scanner.SevHigh:
		return t.red(string(s))
	case scanner.SevMedium:
		return t.yellow(string(s))
	case scanner.SevLow:
		return t.blue(string(s))
	case scanner.SevInfo:
		return t.cyan(string(s))
	}
	return string(s)
}

func writeText(w io.Writer, r *scanner.ScanReport, color bool) error {
	t := theme{enabled: color}
	p := func(format string, a ...interface{}) { fmt.Fprintf(w, format, a...) }

	line := strings.Repeat("─", 80)
	p("%s\n", t.bold(line))
	p(" %s %s\n", t.bold("KUBE-DEMENTOR"), t.dim("- Kubernetes Security Scanner (Discovery / Scan / Exploit)"))
	p("%s\n", t.bold(line))

	p(" %s  %s\n", t.bold("Cluster:"), r.Metadata.ClusterName)
	p(" %s  %s\n", t.bold("Context:"), r.Metadata.ContextName)
	p(" %s  %s\n", t.bold("API    :"), r.Metadata.ClusterServer)
	p(" %s  %s %s\n", t.bold("Version:"), r.Metadata.ServerVersion, t.dim("("+r.Metadata.Platform+")"))
	if r.Metadata.User != "" {
		p(" %s  %s\n", t.bold("User   :"), r.Metadata.User)
	}
	p(" %s  %s → %s (%d ms)\n", t.bold("Scan   :"),
		r.Metadata.StartedAt.Format("15:04:05"),
		r.Metadata.FinishedAt.Format("15:04:05"),
		r.Metadata.DurationMillis)
	p(" %s  %s\n", t.bold("Mode   :"), r.Metadata.Mode)
	if len(r.Metadata.NamespacesChecked) > 0 {
		p(" %s  %s\n", t.bold("Scope  :"), strings.Join(r.Metadata.NamespacesChecked, ", "))
	}
	if r.Metadata.Incomplete {
		p(" %s\n", t.yellow("WARNING: incomplete assessment. Missing data is unknown, not evidence of safety."))
	}
	p("\n")

	p(" %s\n", t.bold("[1] CURRENT IDENTITY SNAPSHOT"))
	p("%s\n", t.gray(line))
	id := r.Identity
	p("   cluster-admin          : %s\n", boolStr(t, id.IsClusterAdmin))
	p("   can list secrets (any) : %s\n", boolStr(t, id.AccessibleSecrets > 0))
	p("   can exec into pods     : %s\n", boolStr(t, id.CanExecPods))
	p("   can impersonate        : %s\n", boolStr(t, id.CanImpersonate))
	p("   can port-forward       : %s\n", boolStr(t, id.CanPortForward))
	p("   accessible namespaces  : %d\n", len(id.NamespaceAccess))
	p("   accessible pods        : %d\n", id.AccessiblePods)
	p("   accessible secrets     : %d\n", id.AccessibleSecrets)
	if len(id.HighRiskVerbs) > 0 {
		sort.Strings(id.HighRiskVerbs)
		p("   high-risk verbs        : %s\n", t.yellow(strings.Join(id.HighRiskVerbs, ", ")))
	}
	p("\n")

	p(" %s\n", t.bold("[2] MISCONFIGURATION / VULNERABILITY SUMMARY"))
	p("%s\n", t.gray(line))
	s := r.Summary
	p("   total findings         : %d\n", s.Total)
	p("   %s : %d\n", sevColor(t, scanner.SevCritical), s.BySeverity[scanner.SevCritical])
	p("   %s     : %d\n", sevColor(t, scanner.SevHigh), s.BySeverity[scanner.SevHigh])
	p("   %s   : %d\n", sevColor(t, scanner.SevMedium), s.BySeverity[scanner.SevMedium])
	p("   %s      : %d\n", sevColor(t, scanner.SevLow), s.BySeverity[scanner.SevLow])
	p("   %s     : %d\n", sevColor(t, scanner.SevInfo), s.BySeverity[scanner.SevInfo])
	p("   by category            :\n")
	cats := make([]string, 0, len(s.ByCategory))
	for c := range s.ByCategory {
		cats = append(cats, string(c))
	}
	sort.Strings(cats)
	for _, c := range cats {
		p("     - %-12s %d\n", c, s.ByCategory[scanner.Category(c)])
	}
	p("\n")

	p(" %s\n", t.bold("[3] EXPLOITATION / VERIFICATION RESULTS"))
	p("%s\n", t.gray(line))
	p("   %s          : %d   %s\n", t.bold("exploited"), s.Exploited, t.dim("(actually reproduced)"))
	p("   %s           : %d   %s\n", t.bold("verified"), s.Verified, t.dim("(config still present)"))
	p("   %s   : %d   %s\n", t.bold("false positives"), s.FalsePositives, t.dim("(no longer reproducible)"))
	p("   %s         : %d   %s\n", t.bold("unverified"), s.Unverified, t.dim("(no applicable probe)"))
	p("   %s       : %s/100\n", t.bold("risk score"), riskColor(t, s.RiskScore))
	p("\n")

	p(" %s\n", t.bold("[4] FINDINGS (sorted by severity, worst first)"))
	p("%s\n", t.gray(line))
	for i, f := range r.Findings {
		writeFinding(w, t, i+1, f)
	}
	return nil
}

func writeFinding(w io.Writer, t theme, n int, f scanner.Finding) {
	p := func(format string, a ...interface{}) { fmt.Fprintf(w, format, a...) }

	sev := sevColor(t, f.Severity)
	header := fmt.Sprintf("#%d  [%s]  %s  %s", n, sev, t.bold(f.Title), t.dim("("+f.RuleID+")"))
	p("\n%s\n", header)
	p("   %s %s\n", t.dim("→ target:"), f.Resource.String())
	if f.Description != "" {
		p("   %s %s\n", t.dim("→ why  :"), wrap(f.Description, "     "))
	}
	if f.Evidence != "" {
		p("   %s %s\n", t.dim("→ evid :"), f.Evidence)
	}
	if f.Impact != "" {
		p("   %s %s\n", t.dim("→ impact:"), wrap(f.Impact, "     "))
	}

	if f.Exploit != nil {
		tag := "UNVERIFIED"
		col := t.gray
		if f.Exploit.Exploited {
			tag, col = "EXPLOITED", t.red
		} else if f.Exploit.FalsePositive {
			tag, col = "FALSE POSITIVE", t.green
		} else if f.Exploit.Verified {
			tag, col = "VERIFIED", t.yellow
		}
		p("   %s %s %s\n", t.dim("→ exploit:"), col(tag), t.dim("safety="+f.Exploit.SafetyLevel))
		if f.Exploit.Evidence != "" {
			p("   %s %s\n", t.dim("→ proof:"), wrap(f.Exploit.Evidence, "     "))
		}
		if f.Exploit.Error != "" {
			p("   %s %s\n", t.dim("→ err :"), f.Exploit.Error)
		}
		if f.Exploit.PoC != "" {
			p("   %s\n", t.dim("→ PoC:"))
			for _, ln := range strings.Split(f.Exploit.PoC, "\n") {
				p("     %s\n", t.cyan(ln))
			}
		}
	}
	if f.Recommendation != "" {
		p("   %s %s\n", t.green("→ fix  :"), wrap(f.Recommendation, "     "))
	}
	if f.RemediationYAML != "" {
		p("   %s\n", t.green("→ suggested YAML:"))
		for _, ln := range strings.Split(f.RemediationYAML, "\n") {
			p("     %s\n", t.gray(ln))
		}
	}
	if f.RemediationCmd != "" {
		p("   %s %s\n", t.green("→ fix cmd:"), t.bold(f.RemediationCmd))
	}
	if len(f.References) > 0 {
		p("   %s %s\n", t.dim("→ refs :"), strings.Join(f.References, "  "))
	}
}

func boolStr(t theme, v bool) string {
	if v {
		return t.red("YES")
	}
	return t.green("no")
}

func riskColor(t theme, v int) string {
	if v >= 75 {
		return t.c(cBold+cRed, fmt.Sprintf("%d", v))
	}
	if v >= 40 {
		return t.red(fmt.Sprintf("%d", v))
	}
	if v >= 15 {
		return t.yellow(fmt.Sprintf("%d", v))
	}
	return t.green(fmt.Sprintf("%d", v))
}

func wrap(s, indent string) string {
	const width = 85
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	words := strings.Fields(s)
	line := ""
	for i, w := range words {
		if line == "" {
			line = w
			continue
		}
		if len(line)+1+len(w) > width {
			b.WriteString(line)
			b.WriteString("\n")
			b.WriteString(indent)
			line = w
		} else {
			line += " " + w
		}
		if i == len(words)-1 {
			b.WriteString(line)
		}
	}
	if line != "" && !strings.HasSuffix(b.String(), line) {
		b.WriteString(line)
	}
	return b.String()
}
