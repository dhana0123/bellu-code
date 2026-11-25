package syft

import (
	"fmt"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/canonical"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

// connection is the connection identity attribute of package entities that
// this adapter writes. The package kind is declared by the github schema with
// identity (connection, scope, purl); here scope is the scanned asset id.
const connection = "syft"

// Batch builds the graph batch for one SBOM: a `package` entity per distinct
// purl, and exactly one relation per package to the asset (5.7):
// declares_dependency from a repository, contained_in to an image or host.
// The asset entity carries identity attributes only, so that the batch names
// both relation endpoints. A package without a purl has no identity and gets
// no entity.
//
// The batch Collector is "syft:<asset>", so applying it replaces only this
// asset's packages.
func Batch(t scanners.Target, s bom.SBOM) (batch.Batch, error) {
	assetKind, assetID, rel, err := asset(t)
	if err != nil {
		return batch.Batch{}, err
	}
	assetHash, err := identity.Hash(assetKind, assetID)
	if err != nil {
		return batch.Batch{}, fmt.Errorf("asset identity: %w", err)
	}
	out := batch.Batch{Collector: Name + ":" + assetName(t)}
	out.Entities = append(out.Entities, batch.Entity{Type: assetKind, Identity: assetID, Attributes: map[string]any{"source": Name}})

	seen := map[string]bool{}
	for _, p := range s.Packages {
		if p.Purl == nil || seen[*p.Purl] {
			continue
		}
		seen[*p.Purl] = true
		id := map[string]string{"connection": connection, "scope": assetName(t), "purl": *p.Purl}
		h, err := identity.Hash("package", id)
		if err != nil {
			return batch.Batch{}, fmt.Errorf("package %q identity: %w", p.Name, err)
		}
		attrs := map[string]any{"source": Name, "name": p.Name}
		if p.Ecosystem != "" {
			attrs["ecosystem"] = p.Ecosystem
		}
		if p.Version != nil {
			attrs["version"] = *p.Version
		}
		if k, ok := canonical.Key(canonical.KindPurl, *p.Purl); ok {
			attrs[canonical.AttrCanonicalKey] = k
		}
		out.Entities = append(out.Entities, batch.Entity{Type: "package", Identity: id, Attributes: attrs})
		from, to := string(h), string(assetHash)
		if rel == "declares_dependency" {
			from, to = to, from
		}
		out.Relations = append(out.Relations, batch.Relation{Type: rel, From: from, To: to})
	}
	return out, nil
}

// asset returns the kind and identity attributes of the target and the
// relation type that links its packages.
func asset(t scanners.Target) (kind string, id map[string]string, rel string, err error) {
	switch t.Type {
	case scanners.TargetRepository:
		return "repository", map[string]string{"path": t.Path}, "declares_dependency", nil
	case scanners.TargetImage:
		return "image", map[string]string{"id": assetName(t)}, "contained_in", nil
	case scanners.TargetHost:
		return "host", map[string]string{"hostname": assetName(t)}, "contained_in", nil
	}
	return "", nil, "", fmt.Errorf("target type %q has no package relation", t.Type)
}
