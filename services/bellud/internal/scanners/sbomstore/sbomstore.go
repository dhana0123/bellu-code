// Package sbomstore keeps the latest good SBOM of each asset in the
// sbom_snapshot table (Requirements 5.12, 5.15).
//
// Storage format: packages_json holds a gzip stream of one JSON document
// {"Subject": "...", "Packages": [ ... ]} whose package objects are the
// encoding/json form of bom.Package. The writer encodes one package at a time
// and the readers decode one package at a time, so neither side holds the
// uncompressed document in memory. content_digest is the asset digest the SBOM
// was built from and package_count is the number of packages.
package sbomstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bom"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// UnknownLicense is the bucket for packages that have no license.
const UnknownLicense = "unknown"

// UnknownEcosystem is the bucket for packages that have no ecosystem.
const UnknownEcosystem = "unknown"

const tsFmt = "2006-01-02T15:04:05.000000000Z"

// Store reads and writes snapshots in one workspace store.
type Store struct {
	db  *sqlite.Store
	now func() time.Time
}

// New returns a Store over db.
func New(db *sqlite.Store) *Store { return &Store{db: db, now: time.Now} }

// Meta describes a stored snapshot.
type Meta struct {
	AssetID      string
	Digest       string
	PackageCount int
	CreatedAt    time.Time
}

// Summary is Meta plus the package counts of the snapshot.
type Summary struct {
	Meta
	Ecosystems map[string]int // purl type; UnknownEcosystem when empty
	Licenses   map[string]int // license; UnknownLicense when none. A package with several licenses counts once under each.
}

// Put replaces the snapshot of assetID in one transaction, so only the latest
// snapshot is kept and a failure leaves the previous one in place.
func (s *Store) Put(ctx context.Context, assetID, digest string, sb bom.SBOM) error {
	blob, err := encode(sb)
	if err != nil {
		return fmt.Errorf("sbomstore: asset %q: %w", assetID, err)
	}
	ws := s.db.WorkspaceID()
	err = s.db.Write(ctx, ws, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO sbom_snapshot
			(workspace_id, asset_id, content_digest, packages_json, package_count, created_at)
			VALUES (?,?,?,?,?,?)`,
			ws, assetID, digest, blob, len(sb.Packages), s.now().UTC().Format(tsFmt))
		return err
	})
	if err != nil {
		return fmt.Errorf("sbomstore: asset %q: %w", assetID, err)
	}
	return nil
}

// Latest returns the stored SBOM of assetID. ok is false when there is none.
func (s *Store) Latest(ctx context.Context, assetID string) (sb bom.SBOM, m Meta, ok bool, err error) {
	m, ok, err = s.Each(ctx, assetID, func(subject string) { sb.Subject = subject }, func(p bom.Package) error {
		sb.Packages = append(sb.Packages, p)
		return nil
	})
	return sb, m, ok, err
}

// Each streams the packages of the snapshot of assetID to fn, one at a time.
// subject, when not nil, is called once before the first package.
func (s *Store) Each(ctx context.Context, assetID string, subject func(string), fn func(bom.Package) error) (Meta, bool, error) {
	m, blob, ok, err := s.load(ctx, assetID)
	if err != nil || !ok {
		return Meta{}, false, err
	}
	if err := decode(blob, subject, fn); err != nil {
		return m, true, fmt.Errorf("sbomstore: asset %q: %w", assetID, err)
	}
	return m, true, nil
}

// List returns one Summary per stored asset, ordered by asset id.
func (s *Store) List(ctx context.Context) ([]Summary, error) {
	rows, err := s.db.DB().QueryContext(ctx, `SELECT asset_id FROM sbom_snapshot WHERE workspace_id = ? ORDER BY asset_id`, s.db.WorkspaceID())
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	sort.Strings(ids)
	var out []Summary
	for _, id := range ids {
		sm := Summary{Ecosystems: map[string]int{}, Licenses: map[string]int{}}
		m, ok, err := s.Each(ctx, id, nil, func(p bom.Package) error {
			sm.Ecosystems[orUnknown(p.Ecosystem, UnknownEcosystem)]++
			if len(p.Licenses) == 0 {
				sm.Licenses[UnknownLicense]++
			}
			for _, l := range p.Licenses {
				sm.Licenses[orUnknown(l, UnknownLicense)]++
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if !ok { // removed since the id query
			continue
		}
		sm.Meta = m
		out = append(out, sm)
	}
	return out, nil
}

func orUnknown(v, unknown string) string {
	if v == "" {
		return unknown
	}
	return v
}

func (s *Store) load(ctx context.Context, assetID string) (Meta, []byte, bool, error) {
	m := Meta{AssetID: assetID}
	var blob []byte
	var created string
	err := s.db.DB().QueryRowContext(ctx, `SELECT content_digest, packages_json, package_count, created_at
		FROM sbom_snapshot WHERE workspace_id = ? AND asset_id = ?`, s.db.WorkspaceID(), assetID).
		Scan(&m.Digest, &blob, &m.PackageCount, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Meta{}, nil, false, nil
	}
	if err != nil {
		return Meta{}, nil, false, fmt.Errorf("sbomstore: asset %q: %w", assetID, err)
	}
	m.CreatedAt, _ = time.Parse(tsFmt, created)
	return m, blob, true, nil
}

func encode(sb bom.SBOM) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	subj, err := json.Marshal(sb.Subject)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(zw, `{"Subject":%s,"Packages":[`, subj)
	enc := json.NewEncoder(zw) // Encode appends a newline, which is valid JSON whitespace
	for i, p := range sb.Packages {
		if i > 0 {
			io.WriteString(zw, ",")
		}
		if err := enc.Encode(p); err != nil {
			return nil, err
		}
	}
	io.WriteString(zw, "]}")
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decode(blob []byte, subject func(string), fn func(bom.Package) error) error {
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return err
	}
	defer zr.Close()
	dec := json.NewDecoder(zr)
	if _, err := dec.Token(); err != nil { // {
		return err
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return err
		}
		switch k {
		case "Subject":
			var v string
			if err := dec.Decode(&v); err != nil {
				return err
			}
			if subject != nil {
				subject(v)
			}
		case "Packages":
			if _, err := dec.Token(); err != nil { // [
				return err
			}
			for dec.More() {
				var p bom.Package
				if err := dec.Decode(&p); err != nil {
					return err
				}
				if err := fn(p); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // ]
				return err
			}
		default:
			return fmt.Errorf("unexpected key %v", k)
		}
	}
	_, err = dec.Token() // }
	return err
}
