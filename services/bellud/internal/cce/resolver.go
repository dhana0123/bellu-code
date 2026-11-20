package cce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrAmbiguousKey means more than one Stable_ID holds the same normalized key.
// The Resolver returns no match rather than choosing one.
var ErrAmbiguousKey = errors.New("identity key matches more than one stable id")

// Resolver resolves identity keys to Stable_IDs.
type Resolver interface {
	// ResolveExact compares the normalized key by exact string equality.
	// It never returns a fuzzy match.
	ResolveExact(ctx context.Context, ws WorkspaceID, key IdentityKey) (StableID, bool, error)
	// ProposeFuzzy returns scored proposals. They are never auto-promoted.
	ProposeFuzzy(ctx context.Context, ws WorkspaceID, q string, limit int) ([]Proposal, error)
}

// SQLResolver resolves keys against stable_entity rows whose attrs hold the
// normalized key under "canonical_key".
type SQLResolver struct {
	DB *sql.DB
}

// ResolveExact implements Resolver. Invalid keys return an error, no match,
// and touch nothing.
func (r SQLResolver) ResolveExact(ctx context.Context, ws WorkspaceID, key IdentityKey) (StableID, bool, error) {
	norm, err := Normalize(key)
	if err != nil {
		return "", false, err
	}
	rows, err := r.DB.QueryContext(ctx,
		`SELECT DISTINCT stable_id FROM stable_entity
		 WHERE workspace_id = ? AND json_extract(attrs, '$.canonical_key') = ?
		 ORDER BY stable_id LIMIT 2`, string(ws), norm)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	var ids []StableID
	for rows.Next() {
		var id StableID
		if err := rows.Scan(&id); err != nil {
			return "", false, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	switch len(ids) {
	case 0:
		return "", false, nil
	case 1:
		return ids[0], true, nil
	}
	return "", false, fmt.Errorf("%w: %q", ErrAmbiguousKey, norm)
}

// ProposeFuzzy is not implemented yet; fuzzy proposals arrive with the
// correlation work. It returns no proposals.
func (r SQLResolver) ProposeFuzzy(context.Context, WorkspaceID, string, int) ([]Proposal, error) {
	return nil, nil
}

var _ Resolver = SQLResolver{}
