package evasion

import (
	"fmt"
	"sync/atomic"

	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

type NoiseMeter struct {
	SSAR       uint64
	ListCalls  uint64
	GetCalls   uint64
	DryRunPOST uint64
}

func (m *NoiseMeter) BumpSSAR()   { atomic.AddUint64(&m.SSAR, 1) }
func (m *NoiseMeter) BumpList()   { atomic.AddUint64(&m.ListCalls, 1) }
func (m *NoiseMeter) BumpGet()    { atomic.AddUint64(&m.GetCalls, 1) }
func (m *NoiseMeter) BumpDryRun() { atomic.AddUint64(&m.DryRunPOST, 1) }

func (m *NoiseMeter) Snapshot() (ssar, list, get, dry uint64, level string) {
	ssar = atomic.LoadUint64(&m.SSAR)
	list = atomic.LoadUint64(&m.ListCalls)
	get = atomic.LoadUint64(&m.GetCalls)
	dry = atomic.LoadUint64(&m.DryRunPOST)
	total := ssar + list + get + dry
	switch {
	case total == 0:
		level = "silent"
	case total < 50:
		level = "quiet"
	case total < 500:
		level = "moderate"
	case total < 2500:
		level = "loud"
	default:
		level = "very-loud"
	}
	return
}

func (m *NoiseMeter) ToFinding(surface *DetectionSurface) scanner.Finding {
	ssar, list, get, dry, level := m.Snapshot()
	ev := fmt.Sprintf("SSAR=%d list=%d get=%d dryRun=%d (level=%s)", ssar, list, get, dry, level)
	var worst string
	if surface != nil {
		worst = surface.Worst
	} else {
		worst = "unknown"
	}
	return scanner.Finding{
		RuleID:   "KH-EVA-NOISE",
		Category: scanner.CatEvasion,
		Severity: scanner.SevInfo,
		Title:    "Scanner noise self-meter",
		Description: fmt.Sprintf(`Kube-Dementor tracked every API call it made during this run. An attacker using the same verb mix would generate similar audit-log volume. Current EDR worst-noise posture: %s.

Breakdown:
  SSAR            %d   (verbs: authorization.k8s.io/selfsubjectaccessreviews:create)
  list            %d   (verbs: list)
  get             %d   (verbs: get)
  dryRun POST     %d   (verbs: create / dryRun=All)

Noise level: %s.`, worst, ssar, list, get, dry, level),
		Resource: scanner.Resource{Kind: "Cluster", Name: "noise-meter"},
		Evidence: ev,
		Tags:     []string{"evasion", "noise-meter"},
	}
}
