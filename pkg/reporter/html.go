package reporter

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func writeHTML(w io.Writer, r *scanner.ScanReport) error {
	fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8"/>
<title>Kube-Dementor Report — %s</title>
<style>
  :root { --bg:#0b0c10; --fg:#e6edf3; --dim:#8b949e; --card:#151820; --line:#2a2f3a; }
  body { margin:0; font-family: ui-sans-serif,system-ui,Inter,Roboto,sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:24px 32px; border-bottom:1px solid var(--line); }
  h1 { margin:0; font-size:22px; }
  h1 small { color:var(--dim); font-weight:normal; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap:16px; padding:24px 32px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; }
  .card h3 { margin:0 0 8px 0; font-size:12px; text-transform:uppercase; color:var(--dim); letter-spacing:.08em; }
  .card .n { font-size:28px; font-weight:700; }
  .sev { padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; }
  .sev.CRITICAL { background:#3a0d10; color:#ff4d56; border:1px solid #ff4d56; }
  .sev.HIGH     { background:#3a200a; color:#ff9f43; border:1px solid #ff9f43; }
  .sev.MEDIUM   { background:#2a2a0a; color:#f1c40f; border:1px solid #f1c40f; }
  .sev.LOW      { background:#0a1a2a; color:#4fc3f7; border:1px solid #4fc3f7; }
  .sev.INFO     { background:#0a2a1a; color:#2ecc71; border:1px solid #2ecc71; }
  main { padding:0 32px 40px; }
  details { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:12px 16px; margin-bottom:10px; }
  details summary { cursor:pointer; display:flex; gap:12px; align-items:center; }
  details summary .t { flex:1; }
  pre { background:#000; color:#e6edf3; padding:12px; border-radius:8px; overflow:auto; font-size:12px; line-height:1.4; }
  code { color:#7ee787; }
  .tag { display:inline-block; padding:2px 6px; border:1px solid var(--line); border-radius:6px; font-size:10px; color:var(--dim); margin-right:6px; }
  .exploit-EXPLOITED    { color:#ff4d56; font-weight:700; }
  .exploit-VERIFIED     { color:#f1c40f; font-weight:700; }
  .exploit-FALSE        { color:#2ecc71; font-weight:700; }
  .exploit-UNVERIFIED   { color:var(--dim); }
  .fix { color:#7ee787; }
  table { width:100%%; border-collapse:collapse; }
  td,th { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); font-size:13px; }
</style>
</head><body>
<header>
  <h1>Kube-Dementor Report <small>%s · %s · %s</small></h1>
</header>
<div class="grid">
`, html.EscapeString(r.Metadata.ClusterName),
		html.EscapeString(r.Metadata.ClusterName),
		html.EscapeString(r.Metadata.ContextName),
		r.Metadata.FinishedAt.Format(time.RFC3339))

	s := r.Summary
	cards := []struct {
		title string
		val   string
		cls   string
	}{
		{"Total findings", fmt.Sprint(s.Total), ""},
		{"Critical", fmt.Sprint(s.BySeverity[scanner.SevCritical]), "CRITICAL"},
		{"High", fmt.Sprint(s.BySeverity[scanner.SevHigh]), "HIGH"},
		{"Medium", fmt.Sprint(s.BySeverity[scanner.SevMedium]), "MEDIUM"},
		{"Low", fmt.Sprint(s.BySeverity[scanner.SevLow]), "LOW"},
		{"Exploited", fmt.Sprint(s.Exploited), "CRITICAL"},
		{"Verified", fmt.Sprint(s.Verified), "HIGH"},
		{"False-positives", fmt.Sprint(s.FalsePositives), "INFO"},
		{"Risk score", fmt.Sprintf("%d / 100", s.RiskScore), ""},
	}
	for _, c := range cards {
		fmt.Fprintf(w, `<div class="card"><h3>%s</h3><div class="n"><span class="sev %s">%s</span></div></div>`,
			c.title, c.cls, c.val)
	}
	fmt.Fprintf(w, `</div><main>`)
	if r.Metadata.Incomplete {
		fmt.Fprint(w, `<div class="card" style="margin-bottom:16px;"><strong>Incomplete assessment.</strong> Missing resources and failed authorization checks are unknown, not evidence of a secure cluster.</div>`)
	}

	fmt.Fprintf(w, `<div class="card" style="margin-bottom:16px;">
		<h3>Identity snapshot</h3>
		<table>
		<tr><td>User</td><td>%s</td></tr>
		<tr><td>Cluster-admin</td><td>%v</td></tr>
		<tr><td>Can exec pods</td><td>%v</td></tr>
		<tr><td>Can list secrets</td><td>%v</td></tr>
		<tr><td>Can impersonate</td><td>%v</td></tr>
		<tr><td>Accessible namespaces</td><td>%d</td></tr>
		<tr><td>Accessible pods</td><td>%d</td></tr>
		<tr><td>Accessible secrets</td><td>%d</td></tr>
		</table>
	</div>`,
		html.EscapeString(r.Identity.Username),
		r.Identity.IsClusterAdmin,
		r.Identity.CanExecPods,
		r.Identity.AccessibleSecrets > 0,
		r.Identity.CanImpersonate,
		len(r.Identity.NamespaceAccess),
		r.Identity.AccessiblePods, r.Identity.AccessibleSecrets)

	for i, f := range r.Findings {
		tag := ""
		tagClass := ""
		if f.Exploit != nil {
			switch {
			case f.Exploit.Exploited:
				tag, tagClass = "EXPLOITED", "exploit-EXPLOITED"
			case f.Exploit.FalsePositive:
				tag, tagClass = "FALSE POSITIVE", "exploit-FALSE"
			case f.Exploit.Verified:
				tag, tagClass = "VERIFIED", "exploit-VERIFIED"
			default:
				tag, tagClass = "UNVERIFIED", "exploit-UNVERIFIED"
			}
		}
		fmt.Fprintf(w, `<details><summary>
			<span class="sev %s">%s</span>
			<span class="t"><b>#%d %s</b> <span class="tag">%s</span> %s</span>
			<span class="%s">%s</span>
		</summary>
		<p><b>Target:</b> %s</p>
		<p>%s</p>`,
			f.Severity, f.Severity, i+1,
			html.EscapeString(f.Title), html.EscapeString(f.RuleID), html.EscapeString(f.Resource.String()),
			tagClass, tag,
			html.EscapeString(f.Resource.String()),
			html.EscapeString(f.Description))
		if f.Evidence != "" {
			fmt.Fprintf(w, `<p><b>Evidence:</b> <code>%s</code></p>`, html.EscapeString(f.Evidence))
		}
		if f.Impact != "" {
			fmt.Fprintf(w, `<p><b>Impact:</b> %s</p>`, html.EscapeString(f.Impact))
		}
		if f.Exploit != nil && f.Exploit.PoC != "" {
			fmt.Fprintf(w, `<p><b>Proof-of-Concept:</b></p><pre>%s</pre>`, html.EscapeString(f.Exploit.PoC))
		}
		if f.Recommendation != "" {
			fmt.Fprintf(w, `<p class="fix"><b>Recommendation:</b> %s</p>`, html.EscapeString(f.Recommendation))
		}
		if f.RemediationYAML != "" {
			fmt.Fprintf(w, `<p class="fix"><b>Remediation YAML:</b></p><pre>%s</pre>`, html.EscapeString(f.RemediationYAML))
		}
		if f.RemediationCmd != "" {
			fmt.Fprintf(w, `<p class="fix"><b>Remediation command:</b> <code>%s</code></p>`, html.EscapeString(f.RemediationCmd))
		}
		if len(f.References) > 0 {
			fmt.Fprintf(w, `<p><b>References:</b> %s</p>`, html.EscapeString(strings.Join(f.References, ", ")))
		}
		fmt.Fprintf(w, `</details>`)
	}

	fmt.Fprintf(w, `</main></body></html>`)
	return nil
}
