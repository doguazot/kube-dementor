package profile

import (
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type Kind string

const (
	External Kind = "external"

	Internal Kind = "internal"
)

func Parse(s string) Kind {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "internal", "internal-trust", "intranet":
		return Internal
	default:
		return External
	}
}

func shouldKeep(f scanner.Finding) bool {
	if f.RuleID == "" {
		return true
	}
	rid := strings.ToUpper(f.RuleID)

	for _, t := range f.Tags {
		if strings.HasPrefix(strings.ToUpper(t), "KEV:") {
			return true
		}
	}

	if f.Category == scanner.CatEscape {
		return true
	}

	if strings.HasPrefix(rid, "KH-PATH") {
		return true
	}

	keepRBAC := []string{
		"KH-RBAC-001",
		"KH-RBAC-002",
		"KH-RBAC-003",
		"KH-RBAC-IMP-001", "KH-RBAC-IMP-002", "KH-RBAC-IMP-003",
		"KH-RBAC-006",
		"KH-RBAC-007",
		"KH-RBAC-008",
		"KH-RBAC-WILDCARD-001",
	}
	for _, k := range keepRBAC {
		if rid == k {
			return true
		}
	}

	keepWorkload := []string{
		"KH-WRK-001",
		"KH-WRK-002",
		"KH-WRK-007",
		"KH-WRK-009",
		"KH-WRK-014",
		"KH-WRK-DOCKER-SOCK",
	}
	for _, k := range keepWorkload {
		if rid == k {
			return true
		}
	}

	keepInfra := []string{
		"KH-KUBELET-NOAUTH",
		"KH-KUBELET-ANON",
		"KH-CLUSTER-ETCD-OPEN",
		"KH-CLUSTER-DASHBOARD-OPEN",
		"KH-CLUSTER-API-ANON",
	}
	for _, k := range keepInfra {
		if rid == k {
			return true
		}
	}

	if strings.HasPrefix(rid, "KH-CLOUD-IMDS") || strings.HasPrefix(rid, "KH-CLOUD-IRSA") {
		return true
	}

	if strings.HasPrefix(rid, "KH-ESC-") {
		return true
	}

	return false
}

func demoteOne(s scanner.Severity) scanner.Severity {
	switch s {
	case scanner.SevCritical:
		return scanner.SevHigh
	case scanner.SevHigh:
		return scanner.SevMedium
	case scanner.SevMedium:
		return scanner.SevLow
	default:
		return s
	}
}

func Apply(p Kind, findings []scanner.Finding) int {
	if p != Internal {
		return 0
	}
	demoted := 0
	for i := range findings {
		if shouldKeep(findings[i]) {
			continue
		}
		orig := findings[i].Severity
		newSev := demoteOne(orig)
		if newSev == orig {
			continue
		}
		findings[i].Severity = newSev
		findings[i].Tags = append(findings[i].Tags, "profile:internal-trust:demoted")
		note := "Severity demoted from " + string(orig) +
			" to " + string(newSev) +
			" because the threat profile is 'internal-trust' " +
			"(operator asserted the cluster is not directly reachable from untrusted networks). " +
			"Original severity is preserved in the rule definition; the audit trail is kept in tags."
		if findings[i].Impact == "" {
			findings[i].Impact = note
		} else {
			findings[i].Impact += "\n\n" + note
		}
		demoted++
	}
	return demoted
}
