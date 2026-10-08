package threatintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	kevURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevCacheTTL = 24 * time.Hour
)

type KEV struct {
	FetchedAt time.Time
	Entries   []KEVEntry
	byCVE     map[string]*KEVEntry
}

type KEVEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
}

func (k *KEV) LookupCVE(cve string) *KEVEntry {
	if k == nil || k.byCVE == nil {
		return nil
	}
	return k.byCVE[strings.ToUpper(cve)]
}

func cachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kube-dementor", "cache", "kev.json")
}

func LoadKEV(ctx context.Context) (*KEV, error) {
	p := cachePath()
	if p != "" {
		if st, err := os.Stat(p); err == nil && time.Since(st.ModTime()) < kevCacheTTL {
			return readKEVFile(p)
		}
	}
	k, err := fetchKEV(ctx)
	if err != nil {

		if p != "" {
			if k2, err2 := readKEVFile(p); err2 == nil && k2 != nil {
				return k2, fmt.Errorf("using stale KEV cache (fetch failed: %w)", err)
			}
		}
		return nil, err
	}
	if p != "" {
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if data, err := json.Marshal(k); err == nil {
			_ = os.WriteFile(p, data, 0o600)
		}
	}
	return k, nil
}

func fetchKEV(ctx context.Context) (*KEV, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("KEV fetch: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, err
	}

	var wrap struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, err
	}
	k := &KEV{
		FetchedAt: time.Now(),
		Entries:   wrap.Vulnerabilities,
		byCVE:     make(map[string]*KEVEntry, len(wrap.Vulnerabilities)),
	}
	for i := range k.Entries {
		k.byCVE[strings.ToUpper(k.Entries[i].CVEID)] = &k.Entries[i]
	}
	return k, nil
}

func readKEVFile(p string) (*KEV, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var k KEV
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, err
	}
	k.byCVE = make(map[string]*KEVEntry, len(k.Entries))
	for i := range k.Entries {
		k.byCVE[strings.ToUpper(k.Entries[i].CVEID)] = &k.Entries[i]
	}
	return &k, nil
}

func LoadCachedKEV() (*KEV, error) {
	return readKEVFile(cachePath())
}

func RefreshTrivyDB(ctx context.Context, binary string) (time.Time, error) {
	if binary == "" {
		binary = "trivy"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return time.Time{}, fmt.Errorf("trivy not in PATH: %w", err)
	}
	c, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, binary, "image", "--download-db-only", "--quiet")
	cmd.Env = append(os.Environ(), "TRIVY_NO_PROGRESS=1")
	if err := cmd.Run(); err != nil {
		return time.Time{}, err
	}
	return time.Now(), nil
}

func RefreshNucleiTemplates(ctx context.Context, binary string) (time.Time, error) {
	if binary == "" {
		binary = "nuclei"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return time.Time{}, fmt.Errorf("nuclei not in PATH: %w", err)
	}
	c, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, binary, "-update-templates", "-silent")
	if err := cmd.Run(); err != nil {
		return time.Time{}, err
	}
	return time.Now(), nil
}

var ErrOffline = errors.New("threatintel: offline and no cache")

type Freshness struct {
	TrivyDBAt  time.Time
	NucleiAt   time.Time
	KEVAt      time.Time
	KEVEntries int
	Warnings   []string
}

func Collect(ctx context.Context, wantTrivy, wantNuclei bool) Freshness {
	f := Freshness{}
	if wantTrivy {
		if t, err := RefreshTrivyDB(ctx, ""); err != nil {
			f.Warnings = append(f.Warnings, "trivy refresh: "+err.Error())
		} else {
			f.TrivyDBAt = t
		}
	}
	if wantNuclei {
		if t, err := RefreshNucleiTemplates(ctx, ""); err != nil {
			f.Warnings = append(f.Warnings, "nuclei refresh: "+err.Error())
		} else {
			f.NucleiAt = t
		}
	}
	if k, err := LoadKEV(ctx); err != nil {
		f.Warnings = append(f.Warnings, "KEV: "+err.Error())
		if k != nil {
			f.KEVAt = k.FetchedAt
			f.KEVEntries = len(k.Entries)
		}
	} else if k != nil {
		f.KEVAt = k.FetchedAt
		f.KEVEntries = len(k.Entries)
	}
	return f
}
