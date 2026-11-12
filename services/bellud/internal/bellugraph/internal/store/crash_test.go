// Modified by the Bellu project from upstream Toise (see NOTICE and UPSTREAM.md).

package store

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/model"
)

// TestMain lets this test binary act as a "crash writer" subprocess when the
// BELLU_GRAPH_CRASH_WRITE_DIR environment variable is set: it appends events and exits
// hard, without a clean Close, to simulate a process crash.
func TestMain(m *testing.M) {
	if dir := os.Getenv("BELLU_GRAPH_CRASH_WRITE_DIR"); dir != "" {
		crashWriter(dir)
		return // unreachable: crashWriter exits the process
	}
	os.Exit(m.Run())
}

func crashWriter(dir string) {
	n, err := strconv.Atoi(os.Getenv("BELLU_GRAPH_CRASH_WRITE_N"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad N: %v\n", err)
		os.Exit(3)
	}
	s, err := Open(dir, DefaultConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(4)
	}
	id := model.EntityID("crash-entity")
	for i := 0; i < n; i++ {
		ct := model.EntityCreated
		if i > 0 {
			ct = model.EntityStateChanged
		}
		if err := s.Append(mkEntityEvent(id, ct, time.Unix(int64(1_700_000_000+i), 0).UTC())); err != nil {
			fmt.Fprintf(os.Stderr, "append: %v\n", err)
			os.Exit(5)
		}
	}
	// Crash: exit without Close(). Each Append committed with Sync, so the WAL
	// is durable and must be replayed on reopen.
	os.Exit(0)
}

func TestCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	const n = 50

	cmd := exec.Command(os.Args[0], "-test.run", "TestCrashRecovery") //nolint:gosec // re-exec of the test binary
	cmd.Env = append(os.Environ(),
		"BELLU_GRAPH_CRASH_WRITE_DIR="+dir,
		"BELLU_GRAPH_CRASH_WRITE_N="+strconv.Itoa(n),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crash-writer subprocess failed: %v\n%s", err, out)
	}

	// Reopen the same directory: Pebble must recover all events from the WAL.
	s, err := Open(dir, DefaultConfig())
	if err != nil {
		t.Fatalf("reopen after crash: %v", err)
	}
	defer func() { _ = s.Close() }()

	if got := s.Sequence(); got != n {
		t.Errorf("recovered sequence = %d, want %d", got, n)
	}
	count := 0
	if err := s.Scan(func(_ uint64, _ model.Event) error { count++; return nil }); err != nil {
		t.Fatalf("scan after recovery: %v", err)
	}
	if count != n {
		t.Errorf("recovered %d events, want %d", count, n)
	}
}
