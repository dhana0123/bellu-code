package runtimeevents

import (
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
)

func TestObservedBatchAndMarks(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	evs := []wire.Event{
		{Type: wire.TypeNetworkConnect, Node: "n1", ContainerID: "c1", Args: "dst=10.0.0.5:443", TS: now.Add(-time.Hour)},
		{Type: wire.TypeNetworkConnect, Node: "n1", Args: "10.0.0.6:80", TS: now.Add(-48 * time.Hour)},
		{Type: wire.TypeProcessExec, Node: "n1", Args: "ls"},
		{Type: wire.TypeNetworkConnect, Node: "n1", Args: "no-dest"},
	}
	b, obs := ObservedBatch(evs, now)
	if len(b.Relations) != 2 || len(obs) != 2 || len(b.Entities) != 4 {
		t.Fatalf("batch: %d rels %d ents %d obs", len(b.Relations), len(b.Entities), len(obs))
	}
	if b.Relations[0].Type != "observed_connection" {
		t.Fatal(b.Relations[0].Type)
	}
	marks := MarkPaths([][2]string{{obs[0].From, obs[0].To}, {obs[1].From, obs[1].To}}, obs, now)
	if marks[obs[0].From+"->"+obs[0].To] != MarkSupported {
		t.Fatal("recent observed path must be supported")
	}
	if _, ok := marks[obs[1].From+"->"+obs[1].To]; ok {
		t.Fatal("stale observation must not support")
	}
	if got := MarkPaths(nil, obs[:1], now); got[obs[0].From+"->"+obs[0].To] != MarkContradicted {
		t.Fatal("observation without computed path must be contradicted")
	}
}
