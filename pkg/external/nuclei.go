package external

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os/exec"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type NucleiOptions struct {
	Binary          string
	ExtraTargets    []string
	TemplateTags    []string
	TemplateFilter  string
	Severities      []string
	Timeout         time.Duration
	RateLimit       int
	DisableInteract bool
}

func (o *NucleiOptions) withDefaults() {
	if len(o.TemplateTags) == 0 && o.TemplateFilter == "" {
		o.TemplateTags = []string{"kubernetes", "k8s", "exposure", "misconfig"}
	}
	if len(o.Severities) == 0 {
		o.Severities = []string{"critical", "high", "medium"}
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Minute
	}
	if o.RateLimit <= 0 {
		o.RateLimit = 150
	}
}

type NucleiEvent struct {
	TemplateID   string     `json:"template-id"`
	TemplateName string     `json:"template-name"`
	Type         string     `json:"type"`
	Host         string     `json:"host"`
	MatchedAt    string     `json:"matched-at"`
	ExtractedAt  string     `json:"extracted-at"`
	Info         NucleiInfo `json:"info"`
	Request      string     `json:"request,omitempty"`
	Response     string     `json:"response,omitempty"`
	CURLCommand  string     `json:"curl-command,omitempty"`
	Matched      string     `json:"matched,omitempty"`
	ExtractedRes []string   `json:"extracted-results,omitempty"`
	Timestamp    string     `json:"timestamp"`
}

type NucleiInfo struct {
	Name           string         `json:"name"`
	Author         []string       `json:"author"`
	Tags           []string       `json:"tags"`
	Description    string         `json:"description"`
	Severity       string         `json:"severity"`
	Reference      []string       `json:"reference,omitempty"`
	Classification map[string]any `json:"classification,omitempty"`
}

func Probe(ctx context.Context, apiServer string, services []corev1.Service, opts NucleiOptions) ([]scanner.Finding, error) {
	opts.withDefaults()
	bin, err := ResolveBinary(opts.Binary, "nuclei")
	if err != nil {
		return nil, err
	}

	targets := collectTargets(apiServer, services, opts.ExtraTargets)
	if len(targets) == 0 {
		return nil, nil
	}
	log.Printf("[nuclei] %d target(s): %s", len(targets), strings.Join(targets, ", "))

	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	args := []string{
		"-silent",
		"-jsonl",
		"-rate-limit", fmt.Sprintf("%d", opts.RateLimit),
		"-severity", strings.Join(opts.Severities, ","),
	}
	if opts.DisableInteract {
		args = append(args, "-no-interactsh")
	} else {

		args = append(args, "-no-interactsh")
	}
	if opts.TemplateFilter != "" {
		args = append(args, "-t", opts.TemplateFilter)
	} else if len(opts.TemplateTags) > 0 {
		args = append(args, "-tags", strings.Join(opts.TemplateTags, ","))
	}

	for _, t := range targets {
		args = append(args, "-u", t)
	}

	cmd := exec.CommandContext(cctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var findings []scanner.Finding
	scan := bufio.NewScanner(stdout)
	scan.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev NucleiEvent
		if err := json.Unmarshal(line, &ev); err != nil {

			continue
		}
		findings = append(findings, nucleiToFinding(ev))
	}
	_ = cmd.Wait()
	if cctx.Err() == context.DeadlineExceeded {
		log.Printf("[nuclei] timed out after %s (partial results kept)", opts.Timeout)
	}
	if stderr.Len() > 0 {
		log.Printf("[nuclei] stderr: %s", trimLong(strings.TrimSpace(stderr.String()), 500))
	}
	return findings, nil
}

func collectTargets(apiServer string, services []corev1.Service, extras []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	if apiServer != "" {

		if u, err := url.Parse(apiServer); err == nil && u.Host != "" {
			add(apiServer)
		}
	}
	for _, s := range services {
		switch s.Spec.Type {
		case corev1.ServiceTypeLoadBalancer:
			for _, ing := range s.Status.LoadBalancer.Ingress {
				host := ing.Hostname
				if host == "" {
					host = ing.IP
				}
				if host == "" {
					continue
				}
				for _, p := range s.Spec.Ports {
					if p.Port == 0 {
						continue
					}
					scheme := "http"
					if p.Port == 443 || strings.HasPrefix(strings.ToLower(p.Name), "https") {
						scheme = "https"
					}
					add(fmt.Sprintf("%s://%s:%d", scheme, host, p.Port))
				}
			}
		case corev1.ServiceTypeNodePort:

		}
	}
	for _, e := range extras {
		add(e)
	}
	return out
}

func nucleiToFinding(ev NucleiEvent) scanner.Finding {
	sev := mapSeverity(ev.Info.Severity)
	title := ev.Info.Name
	if title == "" {
		title = ev.TemplateID
	}

	evid := fmt.Sprintf("template=%s host=%s matched=%s",
		ev.TemplateID, ev.Host, trimLong(ev.MatchedAt, 120))
	if len(ev.ExtractedRes) > 0 {
		evid += "\n  extracted: " + trimLong(strings.Join(ev.ExtractedRes, ", "), 200)
	}

	poc := ev.CURLCommand
	if poc == "" && ev.Request != "" {
		poc = trimLong(ev.Request, 500)
	}

	refs := ev.Info.Reference

	return scanner.Finding{
		RuleID:      "KH-NUC-" + ev.TemplateID,
		Category:    scanner.CatExternalScan,
		Severity:    sev,
		Title:       title,
		Description: trimLong(ev.Info.Description, 500),
		Resource: scanner.Resource{
			Kind: "ExternalEndpoint",
			Name: ev.Host,
		},
		Evidence:       evid,
		Impact:         fmt.Sprintf("Nuclei matched %s at %s — this endpoint is externally reachable.", ev.TemplateID, ev.Host),
		Recommendation: "Block external reachability, add authentication, or remove the exposed service.",
		References:     refs,
		Tags:           append([]string{"nuclei"}, ev.Info.Tags...),
	}
}
