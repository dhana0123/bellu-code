package dataclass

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// Name is the adapter name.
const Name = "dataclass"

const adapterVersion = "1"

// Source lists the data store entities of one cloud account target.
type Source interface {
	Stores(ctx context.Context, accountID string) ([]Store, error)
}

// Adapter implements scanners.Adapter.
type Adapter struct {
	src     Source
	results *Results
	userDir string
	sample  Sampling
}

var _ scanners.Adapter = Adapter{}

// New returns the adapter. userDir is ~/.config/bellucode/data-patterns.d.
func New(src Source, results *Results, userDir string) Adapter {
	return Adapter{src: src, results: results, userDir: userDir}
}

func (Adapter) Kind() scanners.Kind { return scanners.KindDataClassification }

func (Adapter) Info() scanners.Info {
	return scanners.Info{Name: Name, Version: adapterVersion, License: "Apache-2.0"}
}

func (Adapter) Applies(t scanners.TargetType) bool { return t == scanners.TargetCloudAccount }

// Digest is empty: the inputs live in the graph, so the job always runs.
func (Adapter) Digest(context.Context, scanners.Target) (string, error) { return "", nil }

// Run classifies the data stores of the account and replaces its stored
// results. A pattern excluded at load is reported as a scanner error and the
// remaining patterns still apply.
func (a Adapter) Run(ctx context.Context, t scanners.Target, out scanners.Sink) error {
	pats, perrs := Load(a.userDir)
	for _, pe := range perrs {
		if err := out.ScannerError(pe.Source+"#"+pe.ID, pe.Cause); err != nil {
			return err
		}
	}
	stores, err := a.src.Stores(ctx, t.ID)
	if err != nil {
		cause := fmt.Errorf("dataclass: account %q: %w", t.ID, err)
		if rerr := out.ScannerError(t.ID, cause.Error()); rerr != nil {
			return errors.Join(cause, rerr)
		}
		return cause
	}
	rows := make([]Row, len(stores))
	for i, s := range stores {
		rows[i] = Row{EntityID: s.ID, Type: s.Type, Classes: pats.Classify(s)}
		if counts, err := a.sample.run(ctx, pats, s); err != nil {
			// A failed sample is a gap for this store only; the others continue.
			if serr := out.ScannerError(s.ID, "missing_data: "+err.Error()); serr != nil {
				return serr
			}
		} else if counts != nil {
			rows[i].MatchCounts = counts
			rows[i].Classes = mergeClasses(rows[i].Classes, counts)
		}
	}
	return a.results.Replace(ctx, t.ID, rows)
}

// Row is the stored classification of one data store.
type Row struct {
	EntityID string
	Type     string
	Classes  []string
	// MatchCounts is class -> number of sampled matches; nil when the store
	// was not sampled. It never holds content.
	MatchCounts map[string]int
}

// Results persists classifications in the data_classification table.
type Results struct {
	db  *sqlite.Store
	now func() time.Time
}

// NewResults returns a Results over db.
func NewResults(db *sqlite.Store) *Results { return &Results{db: db, now: time.Now} }

// Replace upserts rows for the account and deletes rows of the account that
// are not in rows, so stores that left the graph drop out. match_counts is
// written only for rows that were sampled and kept otherwise.
func (r *Results) Replace(ctx context.Context, accountID string, rows []Row) error {
	ws := r.db.WorkspaceID()
	at := r.now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	return r.db.Write(ctx, ws, func(tx *sql.Tx) error {
		keep := map[string]struct{}{}
		for _, row := range rows {
			classes, _ := json.Marshal(row.Classes)
			if row.MatchCounts != nil {
				mc, _ := json.Marshal(row.MatchCounts)
				if _, err := tx.ExecContext(ctx, `INSERT INTO data_classification
					(workspace_id, entity_id, account_id, entity_type, classes, match_counts, updated_at) VALUES (?,?,?,?,?,?,?)
					ON CONFLICT (workspace_id, entity_id) DO UPDATE SET
					account_id = excluded.account_id, entity_type = excluded.entity_type,
					classes = excluded.classes, match_counts = excluded.match_counts, updated_at = excluded.updated_at`,
					ws, row.EntityID, accountID, row.Type, string(classes), string(mc), at); err != nil {
					return err
				}
				keep[row.EntityID] = struct{}{}
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO data_classification
				(workspace_id, entity_id, account_id, entity_type, classes, updated_at) VALUES (?,?,?,?,?,?)
				ON CONFLICT (workspace_id, entity_id) DO UPDATE SET
				account_id = excluded.account_id, entity_type = excluded.entity_type,
				classes = excluded.classes, updated_at = excluded.updated_at`,
				ws, row.EntityID, accountID, row.Type, string(classes), at); err != nil {
				return err
			}
			keep[row.EntityID] = struct{}{}
		}
		old, err := tx.QueryContext(ctx, `SELECT entity_id FROM data_classification WHERE workspace_id = ? AND account_id = ?`, ws, accountID)
		if err != nil {
			return err
		}
		var stale []string
		for old.Next() {
			var id string
			if err := old.Scan(&id); err != nil {
				old.Close()
				return err
			}
			if _, ok := keep[id]; !ok {
				stale = append(stale, id)
			}
		}
		if err := old.Close(); err != nil {
			return err
		}
		for _, id := range stale {
			if _, err := tx.ExecContext(ctx, `DELETE FROM data_classification WHERE workspace_id = ? AND entity_id = ?`, ws, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// Classes returns the stored classes of an entity; ok is false when none are stored.
func (r *Results) Classes(ctx context.Context, entityID string) (classes []string, ok bool, err error) {
	var raw string
	err = r.db.DB().QueryRowContext(ctx, `SELECT classes FROM data_classification WHERE workspace_id = ? AND entity_id = ?`,
		r.db.WorkspaceID(), entityID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return classes, true, json.Unmarshal([]byte(raw), &classes)
}

// storeTypes are the aws_resource types that are data stores (13.1). Redshift
// and OpenSearch join when the AWS schema declares them; the GCP, Azure and
// Kubernetes stores join with their connectors.
var storeTypes = []string{"s3:bucket", "rds:instance", "rds:cluster", "dynamodb:table"}

// GraphSource reads data store entities from the graph.
type GraphSource struct{ Query graph.Query }

// Stores returns the live data store entities of the connection accountID.
func (g GraphSource) Stores(ctx context.Context, accountID string) ([]Store, error) {
	var out []Store
	for _, rt := range storeTypes {
		cursor := ""
		for {
			pg, err := g.Query.Find(ctx, graph.FindQuery{
				Type:       "aws_resource",
				Attributes: map[string]string{"connection": accountID, "resource_type": rt},
				Paging:     graph.Paging{PageSize: 1000, Cursor: cursor},
			})
			if err != nil {
				return nil, err
			}
			for _, e := range pg.Items {
				out = append(out, fromEntity(e, rt))
			}
			if pg.NextCursor == "" {
				break
			}
			cursor = pg.NextCursor
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// fromEntity reads name, tags and schema from the entity attributes: "name"
// (else the last segment of the ARN), "tags" (map) and "schema" (list).
func fromEntity(e graph.Entity, rt string) Store {
	s := Store{ID: string(e.ID), Type: rt}
	s.Name, _ = e.Attributes["name"].(string)
	s.Region, _ = e.Attributes["region"].(string)
	if s.Name == "" {
		arn, _ := e.Attributes["arn"].(string)
		s.Name = arn[strings.LastIndexAny(arn, ":/")+1:]
	}
	switch tags := e.Attributes["tags"].(type) {
	case map[string]any:
		s.Tags = map[string]string{}
		for k, v := range tags {
			s.Tags[k], _ = v.(string)
		}
	case map[string]string:
		s.Tags = tags
	}
	switch sc := e.Attributes["schema"].(type) {
	case []string:
		s.Schema = sc
	case []any:
		for _, v := range sc {
			if str, ok := v.(string); ok {
				s.Schema = append(s.Schema, str)
			}
		}
	}
	return s
}

// maxListIDs bounds one List call.
const maxListIDs = 500

// Get returns the stored row of an entity; ok is false when none is stored.
func (r *Results) Get(ctx context.Context, entityID string) (Row, bool, error) {
	m, err := r.List(ctx, []string{entityID})
	if err != nil {
		return Row{}, false, err
	}
	row, ok := m[entityID]
	return row, ok, nil
}

// List returns the stored rows of the given entities, keyed by entity id.
// Entities without a row are absent. At most 500 ids are read per call.
func (r *Results) List(ctx context.Context, entityIDs []string) (map[string]Row, error) {
	out := map[string]Row{}
	if len(entityIDs) == 0 {
		return out, nil
	}
	if len(entityIDs) > maxListIDs {
		return nil, fmt.Errorf("dataclass: List takes at most %d ids", maxListIDs)
	}
	args := []any{r.db.WorkspaceID()}
	marks := make([]string, len(entityIDs))
	for i, id := range entityIDs {
		marks[i] = "?"
		args = append(args, id)
	}
	rows, err := r.db.DB().QueryContext(ctx, `SELECT entity_id, entity_type, classes, match_counts FROM data_classification
		WHERE workspace_id = ? AND entity_id IN (`+strings.Join(marks, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var row Row
		var classes string
		var mc sql.NullString
		if err := rows.Scan(&row.EntityID, &row.Type, &classes, &mc); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(classes), &row.Classes); err != nil {
			return nil, err
		}
		if mc.Valid && mc.String != "" {
			if err := json.Unmarshal([]byte(mc.String), &row.MatchCounts); err != nil {
				return nil, err
			}
		}
		out[row.EntityID] = row
	}
	return out, rows.Err()
}
