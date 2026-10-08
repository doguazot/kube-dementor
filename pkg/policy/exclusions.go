package policy

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type ExclusionFile struct {
	Version int         `json:"version,omitempty" yaml:"version,omitempty"`
	Notes   string      `json:"notes,omitempty"   yaml:"notes,omitempty"`
	Rules   []Exclusion `json:"rules,omitempty"   yaml:"rules,omitempty"`
}

type Exclusion struct {
	RuleID        string   `json:"ruleId,omitempty"        yaml:"ruleId,omitempty"`
	RuleIDPattern string   `json:"ruleIdPattern,omitempty" yaml:"ruleIdPattern,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty"    yaml:"namespaces,omitempty"`
	ResourceKinds []string `json:"resourceKinds,omitempty" yaml:"resourceKinds,omitempty"`
	NamePattern   string   `json:"namePattern,omitempty"   yaml:"namePattern,omitempty"`
	SeverityMin   string   `json:"severityMin,omitempty"   yaml:"severityMin,omitempty"`
	Reason        string   `json:"reason,omitempty"        yaml:"reason,omitempty"`

	rulePat *regexp.Regexp
	namePat *regexp.Regexp
}

type ExclusionSet struct {
	Entries []Exclusion
	Raw     ExclusionFile
}

func ParseExclusions(data []byte) (*ExclusionSet, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("exclusion payload is empty")
	}
	var raw ExclusionFile
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		err := json.Unmarshal(data, &raw)
		if err != nil {
			var list []Exclusion
			if err2 := json.Unmarshal(data, &list); err2 == nil {
				raw.Rules = list
				err = nil
			}
		}
		if err != nil {
			if err2 := yaml.Unmarshal(data, &raw); err2 != nil {
				return nil, fmt.Errorf("json parse: %w", err)
			}
		}
	} else {
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("yaml parse: %w", err)
		}
	}
	if len(raw.Rules) == 0 {
		return nil, errors.New("exclusion file contains no rules (each rule needs ruleId or ruleIdPattern)")
	}
	set := &ExclusionSet{Raw: raw, Entries: raw.Rules}
	for i := range set.Entries {
		if err := set.Entries[i].compile(); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return set, nil
}

func Load(path string) (*ExclusionSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return ParseExclusions(data)
}

func (e *Exclusion) compile() error {
	if e.RuleID == "" && e.RuleIDPattern == "" {
		return errors.New("exclusion missing ruleId or ruleIdPattern")
	}
	if e.RuleIDPattern != "" {
		re, err := regexp.Compile(e.RuleIDPattern)
		if err != nil {
			return fmt.Errorf("invalid ruleIdPattern: %w", err)
		}
		e.rulePat = re
	}
	if e.NamePattern != "" {
		re, err := regexp.Compile(e.NamePattern)
		if err != nil {
			return fmt.Errorf("invalid namePattern: %w", err)
		}
		e.namePat = re
	}
	if e.SeverityMin != "" {
		if _, ok := sevOrder[strings.ToUpper(e.SeverityMin)]; !ok {
			return fmt.Errorf("invalid severityMin %q (use CRITICAL, HIGH, MEDIUM, LOW or INFO)", e.SeverityMin)
		}
	}
	return nil
}

func (s *ExclusionSet) Match(f scanner.Finding) *Exclusion {
	if s == nil {
		return nil
	}
	for i := range s.Entries {
		e := &s.Entries[i]
		if e.matches(f) {
			return e
		}
	}
	return nil
}

func (e *Exclusion) matches(f scanner.Finding) bool {
	if e.RuleID != "" && e.RuleID != f.RuleID {
		return false
	}
	if e.rulePat != nil && !e.rulePat.MatchString(f.RuleID) {
		return false
	}
	if len(e.Namespaces) > 0 && !contains(e.Namespaces, f.Resource.Namespace) {
		return false
	}
	if len(e.ResourceKinds) > 0 && !contains(e.ResourceKinds, f.Resource.Kind) {
		return false
	}
	if e.namePat != nil && !e.namePat.MatchString(f.Resource.Name) {
		return false
	}
	if e.SeverityMin != "" {
		if severityRankByName(string(f.Severity)) > severityRankByName(e.SeverityMin) {
			return false
		}
	}
	return true
}

func Signature(f scanner.Finding) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s|%s|%s|%s", f.RuleID, f.Resource.Kind, f.Resource.Namespace, f.Resource.Name)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (s *ExclusionSet) Apply(findings []scanner.Finding) (active, suppressed []scanner.Finding, rulesHit []string) {
	if s == nil || len(s.Entries) == 0 {
		return findings, nil, nil
	}
	hits := map[string]bool{}
	for _, f := range findings {
		if e := s.Match(f); e != nil {
			f.Accepted = true
			f.AcceptedScope = "exclusion"
			if e.Reason != "" {
				f.AcceptedReason = e.Reason
			} else {
				f.AcceptedReason = "matched exclusion rule"
			}
			f.AcceptedBy = "exclusion-file"
			suppressed = append(suppressed, f)
			hits[e.RuleID+e.RuleIDPattern] = true
		} else {
			active = append(active, f)
		}
	}
	for k := range hits {
		rulesHit = append(rulesHit, strings.TrimSuffix(k, ""))
	}
	return active, suppressed, rulesHit
}

func DefaultGlobalAcceptPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kube-dementor", "accepted.json")
}

func LoadGlobalAccepts() ([]scanner.GlobalAcceptance, error) {
	p := DefaultGlobalAcceptPath()
	if p == "" {
		return nil, nil
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []scanner.GlobalAcceptance
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func SaveGlobalAccepts(list []scanner.GlobalAcceptance) error {
	p := DefaultGlobalAcceptPath()
	if p == "" {
		return errors.New("no home dir")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

var globalAcceptMu sync.Mutex

func AddGlobalAccept(e scanner.GlobalAcceptance) error {
	globalAcceptMu.Lock()
	defer globalAcceptMu.Unlock()
	list, err := LoadGlobalAccepts()
	if err != nil {
		return fmt.Errorf("load %s: %w", DefaultGlobalAcceptPath(), err)
	}
	for i := range list {
		if list[i].Signature == e.Signature {
			list[i] = e
			return SaveGlobalAccepts(list)
		}
	}
	list = append(list, e)
	return SaveGlobalAccepts(list)
}

func RemoveGlobalAccept(sig string) error {
	globalAcceptMu.Lock()
	defer globalAcceptMu.Unlock()
	list, err := LoadGlobalAccepts()
	if err != nil {
		return fmt.Errorf("load %s: %w", DefaultGlobalAcceptPath(), err)
	}
	out := make([]scanner.GlobalAcceptance, 0, len(list))
	for _, e := range list {
		if e.Signature != sig {
			out = append(out, e)
		}
	}
	return SaveGlobalAccepts(out)
}

func ApplyGlobalAccepts(findings []scanner.Finding, list []scanner.GlobalAcceptance) (active, accepted []scanner.Finding) {
	if len(list) == 0 {
		return findings, nil
	}
	idx := make(map[string]*scanner.GlobalAcceptance, len(list))
	for i := range list {
		idx[list[i].Signature] = &list[i]
	}
	for _, f := range findings {
		sig := f.Signature
		if sig == "" {
			sig = Signature(f)
		}
		if e, ok := idx[sig]; ok {
			f.Accepted = true
			f.AcceptedBy = e.By
			f.AcceptedReason = e.Reason
			f.AcceptedScope = "global"
			f.Signature = sig
			accepted = append(accepted, f)
			continue
		}
		active = append(active, f)
	}
	return active, accepted
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

var sevOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

func severityRankByName(s string) int {
	if r, ok := sevOrder[strings.ToUpper(s)]; ok {
		return r
	}
	return 99
}
