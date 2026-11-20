package sqlite

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

// WorkspaceID and StableID name the workspace and entity a vector belongs to.
type (
	WorkspaceID = string
	StableID    = string
)

const (
	// MaxSearchK is the largest result count Search accepts.
	MaxSearchK = 1000
	// VectorImplSQLiteFlat is the Info().Implementation value of sqliteFlat.
	VectorImplSQLiteFlat = "sqliteFlat"
)

var (
	// ErrDimensionMismatch means a vector's dimension differs from Info().Dimension.
	ErrDimensionMismatch = errors.New("sqlite: vector dimension mismatch")
	// ErrInvalidK means k is outside 1..MaxSearchK.
	ErrInvalidK = errors.New("sqlite: k must be between 1 and 1000")
	// ErrInvalidVector means a vector holds NaN or Inf.
	ErrInvalidVector = errors.New("sqlite: vector contains a non-finite value")
)

// VecFilter narrows a search. An empty field matches everything.
type VecFilter struct {
	SourceRevision string
}

// VecHit is one search result.
type VecHit struct {
	ID    StableID
	Score float32
}

// VecInfo describes an index.
type VecInfo struct {
	Implementation string
	Model          string
	Dimension      int
	Count          int
}

// VectorIndex is local embedding storage and search.
type VectorIndex interface {
	Upsert(ctx context.Context, ws WorkspaceID, id StableID, model string, rev string, vec []float32) error
	Search(ctx context.Context, ws WorkspaceID, q []float32, k int, filter VecFilter) ([]VecHit, error)
	Delete(ctx context.Context, ws WorkspaceID, id StableID) error
	Info() VecInfo
}

// SQLiteFlat stores float32 blobs in the embedding table and searches them
// with a brute-force cosine scan in Go. It needs no SQLite extension.
type SQLiteFlat struct {
	store *Store
	model string
	dim   int
}

var _ VectorIndex = (*SQLiteFlat)(nil)

// NewSQLiteFlat returns an index for one embedding model and dimension.
func NewSQLiteFlat(store *Store, model string, dim int) (*SQLiteFlat, error) {
	if model == "" || dim <= 0 {
		return nil, fmt.Errorf("sqlite: sqliteFlat needs a model and a positive dimension (got %q, %d)", model, dim)
	}
	return &SQLiteFlat{store: store, model: model, dim: dim}, nil
}

// Info reports the implementation, model, dimension and stored vector count.
// Count is -1 if it cannot be read.
func (f *SQLiteFlat) Info() VecInfo {
	info := VecInfo{Implementation: VectorImplSQLiteFlat, Model: f.model, Dimension: f.dim, Count: -1}
	var n int
	err := f.store.db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM embedding WHERE workspace_id = ? AND model = ?",
		f.store.workspaceID, f.model).Scan(&n)
	if err == nil {
		info.Count = n
	}
	return info
}

// Upsert stores vec for id. A model other than the index model or a vector of
// the wrong dimension is rejected and the table is left unchanged.
func (f *SQLiteFlat) Upsert(ctx context.Context, ws WorkspaceID, id StableID, model string, rev string, vec []float32) error {
	if model != f.model {
		return fmt.Errorf("sqlite: model %q does not match index model %q", model, f.model)
	}
	if err := f.checkVector(vec); err != nil {
		return err
	}
	blob := encodeVector(vec)
	return f.store.Write(ctx, ws, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO embedding(workspace_id, stable_id, model, source_revision, dim, vec)
VALUES(?, ?, ?, ?, ?, ?)
ON CONFLICT(workspace_id, stable_id, model) DO UPDATE SET
  source_revision = excluded.source_revision, dim = excluded.dim, vec = excluded.vec`,
			ws, id, model, rev, f.dim, blob)
		return err
	})
}

// Delete removes the vector of id for the index model. A missing id is not an error.
func (f *SQLiteFlat) Delete(ctx context.Context, ws WorkspaceID, id StableID) error {
	return f.store.Write(ctx, ws, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"DELETE FROM embedding WHERE workspace_id = ? AND stable_id = ? AND model = ?", ws, id, f.model)
		return err
	})
}

// Search returns at most k hits ordered by cosine similarity, highest first,
// with ties ordered by ascending id.
func (f *SQLiteFlat) Search(ctx context.Context, ws WorkspaceID, q []float32, k int, filter VecFilter) ([]VecHit, error) {
	if k < 1 || k > MaxSearchK {
		return nil, fmt.Errorf("%w (got %d)", ErrInvalidK, k)
	}
	if err := f.checkVector(q); err != nil {
		return nil, err
	}
	if ws != f.store.workspaceID {
		return nil, fmt.Errorf("%w: search for %q, workspace is %q", ErrWorkspaceMismatch, ws, f.store.workspaceID)
	}
	query := "SELECT stable_id, vec FROM embedding WHERE workspace_id = ? AND model = ? AND dim = ?"
	args := []any{ws, f.model, f.dim}
	if filter.SourceRevision != "" {
		query += " AND source_revision = ?"
		args = append(args, filter.SourceRevision)
	}
	rows, err := f.store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	qnorm := norm(q)
	var hits []VecHit
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, err
		}
		hits = append(hits, VecHit{ID: id, Score: cosine(q, qnorm, blob)})
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].ID < hits[j].ID
	})
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits, nil
}

func (f *SQLiteFlat) checkVector(v []float32) error {
	if len(v) != f.dim {
		return fmt.Errorf("%w: got %d, index dimension is %d", ErrDimensionMismatch, len(v), f.dim)
	}
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return ErrInvalidVector
		}
	}
	return nil
}

func encodeVector(v []float32) []byte {
	b := make([]byte, 4*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(x))
	}
	return b
}

func norm(v []float32) float64 {
	var s float64
	for _, x := range v {
		s += float64(x) * float64(x)
	}
	return math.Sqrt(s)
}

// cosine decodes blob on the fly. A zero-norm vector scores 0.
func cosine(q []float32, qnorm float64, blob []byte) float32 {
	var dot, bn float64
	for i := range q {
		x := float64(math.Float32frombits(binary.LittleEndian.Uint32(blob[4*i:])))
		dot += float64(q[i]) * x
		bn += x * x
	}
	if qnorm == 0 || bn == 0 {
		return 0
	}
	return float32(dot / (qnorm * math.Sqrt(bn)))
}
