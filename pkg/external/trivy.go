package external

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type TrivyOptions struct {
	Binary       string
	MinSeverity  string
	MaxImages    int
	ImageTimeout time.Duration
}

func (o *TrivyOptions) withDefaults() {
	if o.MinSeverity == "" {
		o.MinSeverity = "HIGH"
	}
	if o.ImageTimeout <= 0 {
		o.ImageTimeout = 90 * time.Second
	}
}

type TrivyReport struct {
	ArtifactName string          `json:"ArtifactName"`
	Results      []TrivyResult   `json:"Results"`
	Metadata     TrivyMetadataV1 `json:"Metadata"`
}

type TrivyResult struct {
	Target          string               `json:"Target"`
	Type            string               `json:"Type"`
	Class           string               `json:"Class"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
	Misconfs        []TrivyMisconf       `json:"Misconfigurations"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string         `json:"VulnerabilityID"`
	PkgName          string         `json:"PkgName"`
	InstalledVersion string         `json:"InstalledVersion"`
	FixedVersion     string         `json:"FixedVersion"`
	PrimaryURL       string         `json:"PrimaryURL"`
	Severity         string         `json:"Severity"`
	Title            string         `json:"Title"`
	Description      string         `json:"Description"`
	References       []string       `json:"References"`
	CVSS             map[string]any `json:"CVSS,omitempty"`
}

type TrivyMisconf struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Severity    string `json:"Severity"`
	Description string `json:"Description"`
}

type TrivyMetadataV1 struct {
	ImageID string   `json:"ImageID"`
	Digests []string `json:"RepoDigests"`
}

func ScanImages(ctx context.Context, pods []corev1.Pod, opts TrivyOptions) ([]scanner.Finding, error) {
	opts.withDefaults()
	bin, err := ResolveBinary(opts.Binary, "trivy")
	if err != nil {
		return nil, err
	}

	type usage struct {
		Pods []string
	}
	used := map[string]*usage{}
	for _, p := range pods {
		for _, c := range append(p.Spec.Containers, p.Spec.InitContainers...) {
			img := c.Image
			if img == "" {
				continue
			}
			u, ok := used[img]
			if !ok {
				u = &usage{}
				used[img] = u
			}
			u.Pods = append(u.Pods, p.Namespace+"/"+p.Name)
		}
	}
	if len(used) == 0 {
		return nil, nil
	}

	images := make([]string, 0, len(used))
	for img := range used {
		images = append(images, img)
	}
	sort.Strings(images)
	if opts.MaxImages > 0 && len(images) > opts.MaxImages {
		images = images[:opts.MaxImages]
	}

	log.Printf("[trivy] scanning %d unique image(s), min-severity=%s", len(images), opts.MinSeverity)

	var findings []scanner.Finding
	for i, img := range images {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		log.Printf("[trivy] (%d/%d) %s", i+1, len(images), img)
		rep, err := runTrivyImage(ctx, bin, img, opts)
		if err != nil {
			log.Printf("[trivy] WARN: %s: %v", img, err)
			continue
		}
		pods := used[img].Pods
		findings = append(findings, trivyToFindings(img, pods, rep)...)
	}
	return findings, nil
}

func runTrivyImage(ctx context.Context, bin, image string, opts TrivyOptions) (*TrivyReport, error) {
	cctx, cancel := context.WithTimeout(ctx, opts.ImageTimeout)
	defer cancel()
	args := []string{
		"image",
		"--quiet",
		"--format", "json",
		"--severity", opts.MinSeverity + ",CRITICAL",
		"--scanners", "vuln",
		"--no-progress",
		image,
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {

		var ee *exec.ExitError
		if ok := errAs(err, &ee); ok {
			return nil, fmt.Errorf("trivy exit=%d: %s", ee.ExitCode(), strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var rep TrivyReport
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	return &rep, nil
}

func trivyToFindings(image string, usedBy []string, rep *TrivyReport) []scanner.Finding {
	var out []scanner.Finding
	uniquePods := dedup(usedBy)
	sample := uniquePods
	if len(sample) > 5 {
		sample = sample[:5]
	}

	seen := map[string]bool{}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			key := v.VulnerabilityID + "|" + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true

			sev := mapSeverity(v.Severity)
			title := fmt.Sprintf("%s in %s (%s)", v.VulnerabilityID, v.PkgName, v.InstalledVersion)
			evidence := joinList(
				"image="+image,
				"package="+v.PkgName+"@"+v.InstalledVersion,
				"fixed="+v.FixedVersion,
				"used-by-pods="+fmt.Sprintf("%d", len(uniquePods)),
			)
			desc := v.Title
			if desc == "" {
				desc = trimLong(v.Description, 400)
			}
			rec := "Rebuild image with a patched base and re-roll the deployment."
			if v.FixedVersion != "" {
				rec = fmt.Sprintf("Upgrade %s to %s or later and redeploy.", v.PkgName, v.FixedVersion)
			}
			refs := v.References
			if v.PrimaryURL != "" {
				refs = append([]string{v.PrimaryURL}, refs...)
			}

			primaryPod := ""
			ns, name := "", ""
			if len(uniquePods) > 0 {
				primaryPod = uniquePods[0]
				parts := strings.SplitN(primaryPod, "/", 2)
				if len(parts) == 2 {
					ns, name = parts[0], parts[1]
				}
			}

			f := scanner.Finding{
				RuleID:   "KH-CVE-" + v.VulnerabilityID,
				Category: scanner.CatImageCVE,
				Severity: sev,
				Title:    title,
				Description: fmt.Sprintf("%s\n\nAffected pods (up to 5 shown): %s",
					desc, strings.Join(sample, ", ")),
				Resource: scanner.Resource{
					APIVersion: "v1",
					Kind:       "Pod",
					Namespace:  ns,
					Name:       ifEmpty(name, "image:"+image),
				},
				Evidence:       evidence,
				Impact:         fmt.Sprintf("Remote attackers with network access or code-exec in the container may exploit %s in the %s package.", v.VulnerabilityID, v.PkgName),
				Recommendation: rec,
				RemediationCmd: "kubectl rollout restart deploy/<deployment>   # after rebuilding with the patched base",
				References:     refs,
				Tags:           []string{"cve", v.VulnerabilityID, "trivy"},
			}
			out = append(out, f)
		}
	}
	return out
}

func mapSeverity(s string) scanner.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return scanner.SevCritical
	case "HIGH":
		return scanner.SevHigh
	case "MEDIUM":
		return scanner.SevMedium
	case "LOW":
		return scanner.SevLow
	}
	return scanner.SevInfo
}

func dedup(ss []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func ifEmpty(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

func errAs(err error, target any) bool {
	type asIface interface{ As(any) bool }
	if err == nil {
		return false
	}

	if ee, ok := err.(*exec.ExitError); ok {
		if p, ok2 := target.(**exec.ExitError); ok2 {
			*p = ee
			return true
		}
	}
	return false
}
