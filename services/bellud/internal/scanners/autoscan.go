package scanners

import (
	"context"
	"errors"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// autoScanKinds are the kinds queued after a collection (18.2).
var autoScanKinds = []Kind{KindPosture, KindVulnerability, KindDataClassification}

// autoScanTargets maps a graph entity kind to the target type scanned for it.
var autoScanTargets = map[string]TargetType{
	"repository":  TargetRepository,
	"image":       TargetImage,
	"host":        TargetHost,
	"aws_account": TargetCloudAccount,
}

// AutoScan queues posture, vulnerability and data_classification jobs for the
// scannable assets in a collected batch. It does nothing unless
// scanners.auto_scan is on (18.2).
//
// Wire it as the collectors.Runner batch hook (collectors.WithOnBatch). The
// runner does not report which entities changed (the engine receipt only
// counts them), so every scannable entity of the batch is queued; an asset that
// did not change ends as skipped_unchanged (18.8). Kinds an adapter does not
// handle for the asset and assets the resolver does not know are skipped.
func (m *Manager) AutoScan(ctx context.Context, b graph.Batch) error {
	if !m.cfg.Settings.AutoScan {
		return nil
	}
	var errs []error
	seen := map[string]bool{}
	for _, e := range b.Entities {
		tt, ok := autoScanTargets[e.Type]
		if !ok {
			continue
		}
		id, err := identity.Hash(e.Type, e.Identity)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[string(id)] {
			continue
		}
		seen[string(id)] = true
		for _, k := range autoScanKinds {
			_, err := m.Enqueue(ctx, k, Target{Type: tt, ID: string(id)})
			if err != nil && !errors.Is(err, ErrKindNotApplicable) && !errors.Is(err, ErrTargetNotFound) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
