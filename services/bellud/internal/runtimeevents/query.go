package runtimeevents

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
)

// Stored is one persisted runtime event.
type Stored struct {
	Seq int64 `json:"seq"`
	wire.Event
}

// Sensor is one runtime_sensor status row.
type Sensor struct {
	Node          string           `json:"node"`
	Status        string           `json:"status"`
	Reason        string           `json:"reason,omitempty"`
	Drops         map[string]int64 `json:"drops"`
	RejectedTotal int64            `json:"rejectedTotal"`
	SeenAt        time.Time        `json:"seenAt"`
}

// Ingest validates and stores one event from an already authenticated sender
// (a verified mTLS client), then runs the rules hook. node overrides e.Node.
func (s *Server) Ingest(ctx context.Context, node string, e wire.Event) error {
	if node == "" || len(node) > 253 {
		s.reject()
		return errors.New("runtimeevents: node is required")
	}
	e.Node = node
	if !s.valid(&e) {
		return errors.New("runtimeevents: unknown event type")
	}
	if err := s.store(ctx, e); err != nil {
		return err
	}
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(e)
	}
	return nil
}

// Events lists stored events newest first. before > 0 returns only seq < before.
func (s *Server) Events(ctx context.Context, typ string, before int64, limit int) ([]Stored, error) {
	rows, err := s.cfg.Store.DB().QueryContext(ctx, `SELECT seq, ts, type, COALESCE(node,''), COALESCE(namespace,''), COALESCE(pod,''),
 COALESCE(container_id,''), COALESCE(process_path,''), COALESCE(args,''), COALESCE(user,''), unavailable
 FROM runtime_event WHERE workspace_id=? AND (?='' OR type=?) AND (?<=0 OR seq<?) ORDER BY seq DESC LIMIT ?`,
		s.cfg.WorkspaceID, typ, typ, before, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Stored{}
	for rows.Next() {
		var e Stored
		var ts, un string
		if err := rows.Scan(&e.Seq, &ts, &e.Type, &e.Node, &e.Namespace, &e.Pod, &e.ContainerID, &e.ProcessPath, &e.Args, &e.User, &un); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		_ = json.Unmarshal([]byte(un), &e.Unavailable)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Sensors lists the sensor status rows by node.
func (s *Server) Sensors(ctx context.Context) ([]Sensor, error) {
	rows, err := s.cfg.Store.DB().QueryContext(ctx, `SELECT node, status, COALESCE(reason,''), drops, rejected_total, seen_at
 FROM runtime_sensor WHERE workspace_id=? ORDER BY node`, s.cfg.WorkspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Sensor{}
	for rows.Next() {
		var x Sensor
		var drops, seen string
		if err := rows.Scan(&x.Node, &x.Status, &x.Reason, &drops, &x.RejectedTotal, &seen); err != nil {
			return nil, err
		}
		x.Drops = map[string]int64{}
		_ = json.Unmarshal([]byte(drops), &x.Drops)
		x.SeenAt, _ = time.Parse(time.RFC3339Nano, seen)
		out = append(out, x)
	}
	return out, rows.Err()
}
