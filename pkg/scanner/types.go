package scanner

import (
	"fmt"
	"sort"
	"time"
)

type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
)

var severityOrder = map[Severity]int{
	SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInfo: 4,
}

type Category string

const (
	CatWorkload     Category = "workload"
	CatRBAC         Category = "rbac"
	CatSecret       Category = "secret"
	CatNetwork      Category = "network"
	CatClusterLevel Category = "cluster"
	CatSupplyChain  Category = "supply-chain"
	CatAudit        Category = "audit"
	CatImageCVE     Category = "image-cve"
	CatExternalScan Category = "external-scan"
	CatAttackPath   Category = "attack-path"
	CatAdmission    Category = "admission"
	CatKubelet      Category = "kubelet"
	CatEscape       Category = "escape"
	CatCloud        Category = "cloud-credentials"
	CatPersistence  Category = "persistence"
	CatEvasion      Category = "evasion"
	CatRuntime      Category = "runtime"
	CatCNI          Category = "cni"
	CatServiceMesh  Category = "service-mesh"
)

type Resource struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

func (r Resource) String() string {
	if r.Namespace == "" {
		return fmt.Sprintf("%s/%s", r.Kind, r.Name)
	}
	return fmt.Sprintf("%s/%s/%s", r.Kind, r.Namespace, r.Name)
}

type ExploitResult struct {
	Attempted     bool      `json:"attempted"`
	Verified      bool      `json:"verified"`
	Exploited     bool      `json:"exploited"`
	FalsePositive bool      `json:"falsePositive"`
	SafetyLevel   string    `json:"safetyLevel"`
	Commands      []string  `json:"commands"`
	PoC           string    `json:"poc"`
	Evidence      string    `json:"evidence"`
	Error         string    `json:"error,omitempty"`
	StartedAt     time.Time `json:"startedAt,omitempty"`
	FinishedAt    time.Time `json:"finishedAt,omitempty"`
}

type Finding struct {
	ID              string         `json:"id"`
	RuleID          string         `json:"ruleId"`
	Category        Category       `json:"category"`
	Severity        Severity       `json:"severity"`
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	Resource        Resource       `json:"resource"`
	Evidence        string         `json:"evidence,omitempty"`
	Impact          string         `json:"impact,omitempty"`
	Recommendation  string         `json:"recommendation"`
	RemediationYAML string         `json:"remediationYaml,omitempty"`
	RemediationCmd  string         `json:"remediationCmd,omitempty"`
	References      []string       `json:"references,omitempty"`
	MitreATTACK     []string       `json:"mitreAttack,omitempty"`
	Tags            []string       `json:"tags,omitempty"`
	DetectedAt      time.Time      `json:"detectedAt"`
	Exploit         *ExploitResult `json:"exploit,omitempty"`

	AttackPath *GraphSnapshot `json:"attackPath,omitempty"`

	Shell *ShellTarget `json:"shell,omitempty"`

	Signature string `json:"signature,omitempty"`

	Accepted       bool   `json:"accepted,omitempty"`
	AcceptedReason string `json:"acceptedReason,omitempty"`
	AcceptedBy     string `json:"acceptedBy,omitempty"`
	AcceptedScope  string `json:"acceptedScope,omitempty"`
}

type ShellTarget struct {
	Container string `json:"container"`
	Scope     string `json:"scope"`
	NodeName  string `json:"nodeName,omitempty"`
	Verified  bool   `json:"verified"`
}

func (f Finding) SeverityRank() int {
	if r, ok := severityOrder[f.Severity]; ok {
		return r
	}
	return 99
}

type ScanReport struct {
	Metadata ScanMetadata     `json:"metadata"`
	Identity IdentitySnapshot `json:"identity"`
	Summary  ScanSummary      `json:"summary"`
	Findings []Finding        `json:"findings"`

	AcceptedFindings []Finding `json:"acceptedFindings,omitempty"`

	Graph *GraphSnapshot `json:"graph,omitempty"`
}

type GraphSnapshot struct {
	Me    string      `json:"me,omitempty"`
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type GraphNode struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	HighValue bool   `json:"highValue,omitempty"`
	Status    string `json:"status,omitempty"`
	Phase     string `json:"phase,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type GraphEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Note   string `json:"note,omitempty"`
	Status string `json:"status,omitempty"`
}

type ScanMetadata struct {
	ScanID            string    `json:"scanId"`
	ContextName       string    `json:"contextName"`
	ClusterName       string    `json:"clusterName"`
	ClusterServer     string    `json:"clusterServer"`
	User              string    `json:"user"`
	ServerVersion     string    `json:"serverVersion"`
	Platform          string    `json:"platform"`
	Namespace         string    `json:"namespace"`
	StartedAt         time.Time `json:"startedAt"`
	FinishedAt        time.Time `json:"finishedAt"`
	DurationMillis    int64     `json:"durationMs"`
	Mode              string    `json:"mode"`
	RulesEvaluated    int       `json:"rulesEvaluated"`
	TargetsScanned    int       `json:"targetsScanned"`
	NamespacesChecked []string  `json:"namespacesChecked,omitempty"`

	CollectionIssues []CollectionIssue `json:"collectionIssues,omitempty"`
	Incomplete       bool              `json:"incomplete,omitempty"`
	SafetyGuard      bool              `json:"safetyGuard"`
	SafetyViolations []string          `json:"safetyViolations,omitempty"`
	ExternalScanners []string          `json:"externalScanners,omitempty"`

	LiveExploits []LiveExploitEntry `json:"liveExploits,omitempty"`

	Acceptances []Acceptance `json:"acceptances,omitempty"`

	ExclusionsApplied []string `json:"exclusionsApplied,omitempty"`

	ThreatIntel *ThreatIntelStatus `json:"threatIntel,omitempty"`

	Profile string `json:"profile,omitempty"`

	EscapePosture string `json:"escapePosture,omitempty"`
}

type CollectionIssue struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Operation string `json:"operation"`
	Error     string `json:"error"`
}

type ThreatIntelStatus struct {
	TrivyDBUpdated      time.Time `json:"trivyDbUpdated,omitempty"`
	NucleiTemplates     time.Time `json:"nucleiTemplatesUpdated,omitempty"`
	KEVFetched          time.Time `json:"kevFetched,omitempty"`
	KEVEntries          int       `json:"kevEntries,omitempty"`
	KubeDementorVersion string    `json:"kubeDementorVersion,omitempty"`
	Warnings            []string  `json:"warnings,omitempty"`
}

type LiveExploitEntry struct {
	At         time.Time `json:"at"`
	FindingID  string    `json:"findingId"`
	RuleID     string    `json:"ruleId"`
	Capability string    `json:"capability"`
	Ok         bool      `json:"ok"`
	Evidence   string    `json:"evidence,omitempty"`
	Error      string    `json:"error,omitempty"`

	EvidenceBundle *EvidenceBundle `json:"evidenceBundle,omitempty"`
}

type EvidenceBundle struct {
	Command  string         `json:"command,omitempty"`
	Stdout   string         `json:"stdout,omitempty"`
	Stderr   string         `json:"stderr,omitempty"`
	Data     any            `json:"data,omitempty"`
	Duration string         `json:"duration,omitempty"`
	Request  map[string]any `json:"request,omitempty"`
	Response map[string]any `json:"response,omitempty"`
	ExitCode int            `json:"exitCode"`
}

type Acceptance struct {
	FindingID string    `json:"findingId"`
	RuleID    string    `json:"ruleId"`
	Signature string    `json:"signature"`
	By        string    `json:"by"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
	Scope     string    `json:"scope"`
}

type GlobalAcceptance struct {
	Signature string    `json:"signature"`
	RuleID    string    `json:"ruleId"`
	Title     string    `json:"title,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	By        string    `json:"by"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
}

type IdentitySnapshot struct {
	Username          string   `json:"username,omitempty"`
	UID               string   `json:"uid,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	IsClusterAdmin    bool     `json:"isClusterAdmin"`
	NamespaceAccess   []string `json:"namespaceAccess"`
	HighRiskVerbs     []string `json:"highRiskVerbs"`
	AccessibleSecrets int      `json:"accessibleSecrets"`
	AccessiblePods    int      `json:"accessiblePods"`
	CanExecPods       bool     `json:"canExecPods"`
	CanImpersonate    bool     `json:"canImpersonate"`
	CanPortForward    bool     `json:"canPortForward"`

	ImpersonatableUsers           []string                    `json:"impersonatableUsers,omitempty"`
	ImpersonatableGroups          []string                    `json:"impersonatableGroups,omitempty"`
	ImpersonatableServiceAccounts []string                    `json:"impersonatableServiceAccounts,omitempty"`
	TokenRequestSAs               []string                    `json:"tokenRequestSAs,omitempty"`
	DiscoverySource               string                      `json:"discoverySource,omitempty"`
	NamespacedRules               map[string][]NamespacedRule `json:"namespacedRules,omitempty"`
}

type NamespacedRule struct {
	Verbs           []string `json:"verbs,omitempty"`
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

type ScanSummary struct {
	Total          int              `json:"total"`
	BySeverity     map[Severity]int `json:"bySeverity"`
	ByCategory     map[Category]int `json:"byCategory"`
	Verified       int              `json:"verified"`
	Exploited      int              `json:"exploited"`
	FalsePositives int              `json:"falsePositives"`
	Unverified     int              `json:"unverified"`
	Accepted       int              `json:"accepted"`
	RiskScore      int              `json:"riskScore"`
}

func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].SeverityRank() != fs[j].SeverityRank() {
			return fs[i].SeverityRank() < fs[j].SeverityRank()
		}
		if fs[i].Category != fs[j].Category {
			return fs[i].Category < fs[j].Category
		}
		return fs[i].Resource.String() < fs[j].Resource.String()
	})
}

func ComputeSummary(fs []Finding) ScanSummary {
	s := ScanSummary{
		BySeverity: make(map[Severity]int),
		ByCategory: make(map[Category]int),
	}
	for _, f := range fs {
		s.Total++
		s.BySeverity[f.Severity]++
		s.ByCategory[f.Category]++
		if f.Exploit != nil {
			if f.Exploit.Exploited {
				s.Exploited++
				s.Verified++
			} else if f.Exploit.Verified {
				s.Verified++
			} else if f.Exploit.FalsePositive {
				s.FalsePositives++
			}
			if !f.Exploit.Attempted {
				s.Unverified++
			}
		} else {
			s.Unverified++
		}
	}
	s.RiskScore = computeRiskScore(s)
	return s
}

func computeRiskScore(s ScanSummary) int {
	score := s.BySeverity[SevCritical]*25 +
		s.BySeverity[SevHigh]*10 +
		s.BySeverity[SevMedium]*4 +
		s.BySeverity[SevLow]*1

	score += s.Exploited * 5
	if score > 100 {
		score = 100
	}
	return score
}
