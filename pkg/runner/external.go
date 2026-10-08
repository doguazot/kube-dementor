package runner

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/external"
	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
)

func runTrivyPhase(ctx context.Context, inv *scanner.Inventory, opts Options) ([]scanner.Finding, error) {
	started := time.Now()
	log.Printf("[runner] trivy: enabled")
	extra, err := external.ScanImages(ctx, inv.Pods, external.TrivyOptions{
		Binary:       opts.TrivyBinary,
		MinSeverity:  "HIGH",
		MaxImages:    0,
		ImageTimeout: 90 * time.Second,
	})
	if err != nil {
		if errors.Is(err, external.ErrBinaryMissing) {
			log.Printf("[runner] trivy: binary missing — skipping (install: brew install trivy / https://aquasecurity.github.io/trivy)")
			return nil, nil
		}
		return nil, err
	}
	log.Printf("[runner] trivy: %d CVE finding(s) in %s", len(extra), time.Since(started).Truncate(time.Millisecond))
	return extra, nil
}

func runNucleiPhase(ctx context.Context, sess *kubectx.Session, inv *scanner.Inventory, opts Options) ([]scanner.Finding, error) {
	started := time.Now()
	log.Printf("[runner] nuclei: enabled")
	extra, err := external.Probe(ctx, sess.Info.ClusterServer, inv.Services, external.NucleiOptions{
		Binary:       opts.NucleiBinary,
		ExtraTargets: opts.NucleiTargets,
	})
	if err != nil {
		if errors.Is(err, external.ErrBinaryMissing) {
			log.Printf("[runner] nuclei: binary missing — skipping (install: https://github.com/projectdiscovery/nuclei)")
			return nil, nil
		}
		return nil, err
	}
	log.Printf("[runner] nuclei: %d finding(s) in %s", len(extra), time.Since(started).Truncate(time.Millisecond))
	return extra, nil
}
