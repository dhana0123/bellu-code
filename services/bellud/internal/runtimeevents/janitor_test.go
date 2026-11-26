package runtimeevents

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestSweepRetentionAndSize(t *testing.T) {
	_, db, _ := setup(t)
	now := time.Now().UTC()
	ins := func(age time.Duration, size int) {
		_, err := db.DB().Exec(`INSERT INTO runtime_event (workspace_id, ts, type, size_bytes) VALUES ('ws1', ?, 'shell_spawn', ?)`,
			now.Add(-age).Format(time.RFC3339Nano), size)
		if err != nil {
			t.Fatal(err)
		}
	}
	ins(10*24*time.Hour, 10) // too old
	for i := 5; i >= 1; i-- {
		ins(time.Duration(i)*time.Hour, 100)
	}
	j := &Janitor{cfg: JanitorConfig{Store: db, WorkspaceID: "ws1", RetentionDays: 7, MaxBytes: 250, Now: func() time.Time { return now }}}
	j.cfg.normalize()
	n, err := j.Sweep(context.Background())
	if err != nil || n != 4 { // 1 aged + 3 oldest by size
		t.Fatalf("deleted %d err %v", n, err)
	}
	var minAge int
	if err := db.DB().QueryRow(`SELECT count(*) FROM runtime_event WHERE size_bytes=100`).Scan(&minAge); err != nil || minAge != 2 {
		t.Fatalf("remaining %d %v", minAge, err)
	}
	if n, _ := j.Sweep(context.Background()); n != 0 {
		t.Fatal(fmt.Sprint("second sweep deleted ", n))
	}
}
