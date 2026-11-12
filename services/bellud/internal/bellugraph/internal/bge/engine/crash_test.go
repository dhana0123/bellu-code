package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/graph"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/ident"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

const (
	crashBatchSize = 1000
	crashMaxBatch  = 200
)

func crashHostName(batchNo, i int) string { return fmt.Sprintf("crash-%d-%d", batchNo, i) }

// crashBatch is the n-th Batch of the child: crashBatchSize new hosts.
func crashBatch(n int) batch.Batch {
	b := batch.Batch{Collector: "crash", Entities: make([]batch.Entity, crashBatchSize)}
	for i := range b.Entities {
		b.Entities[i] = batch.Entity{
			Type: "host", Identity: map[string]string{"hostname": crashHostName(n, i)},
			Attributes: map[string]any{"batch": int64(n)},
		}
	}
	return b
}

// crashChild applies Batches in a loop until the parent kills it.
func crashChild(dir string, start int) {
	c, err := Open(dir, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		fmt.Fprintln(os.Stderr, "child open:", err)
		os.Exit(2)
	}
	fmt.Println("ready")
	for n := start; n < start+crashMaxBatch; n++ {
		if _, err := c.Apply(context.Background(), crashBatch(n), ModePartial); err != nil {
			fmt.Fprintln(os.Stderr, "child apply:", err)
			os.Exit(2)
		}
	}
	os.Exit(0)
}

// TestCrashMidApply kills a child process with SIGKILL while it applies
// Batches and checks that each Batch is present entirely or not at all after
// the store is reopened, and that replay equality holds.
func TestCrashMidApply(t *testing.T) {
	if dir := os.Getenv("BGE_CRASH_DIR"); os.Getenv("BGE_CRASH_CHILD") == "1" && dir != "" {
		start, _ := strconv.Atoi(os.Getenv("BGE_CRASH_START"))
		crashChild(dir, start)
		return
	}
	if testing.Short() {
		t.Skip("crash test skipped under -short")
	}
	if runtime.GOOS == "windows" {
		t.Skip("crash test is not supported on Windows")
	}
	dir := t.TempDir()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	next := 0
	for round := 0; round < 20; round++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCrashMidApply$")
		cmd.Env = append(os.Environ(), "BGE_CRASH_CHILD=1", "BGE_CRASH_DIR="+dir, "BGE_CRASH_START="+strconv.Itoa(next))
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "ready\n" {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("round %d: child did not start: %q, %v", round, line, err)
		}
		time.Sleep(time.Duration(rng.Intn(200)) * time.Millisecond)
		_ = cmd.Process.Kill() // SIGKILL on Unix
		_ = cmd.Wait()

		c, err := Open(dir, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatalf("round %d: reopen after kill: %v", round, err)
		}
		present := checkCrashBatches(t, round, c.g)
		if present < next {
			t.Fatalf("round %d: %d batches survived, %d were present before", round, present, next)
		}
		next = present
		// Replay equality: the log from empty equals the recovered Projection.
		replay := graph.New()
		v := c.st.NewView()
		it, err := v.Events(1, 0)
		if err != nil {
			t.Fatal(err)
		}
		for it.Next() {
			ev, err := it.Event()
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			replay.Fold(ev)
		}
		if err := it.Err(); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		it.Close()
		v.Close()
		if !c.g.Equal(replay) {
			t.Fatalf("round %d: recovered Projection differs from the full replay", round)
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatalf("round %d: close: %v", round, err)
		}
	}
	t.Logf("applied %d batches of %d entities across 20 kills", next, crashBatchSize)
}

// checkCrashBatches verifies all-or-none for every Batch the children can
// have attempted and returns the number of Batches present. Present Batches
// must form a prefix, because the child applies them in order and each Batch
// is one atomic write.
func checkCrashBatches(t *testing.T, round int, g *graph.Graph) int {
	t.Helper()
	present := 0
	for n := 0; ; n++ {
		have := 0
		for _, id := range crashIDs(t, n) {
			{
				if e, ok := g.Entity(id); ok && e.Live {
					have++
				}
			}
		}
		if have != 0 && have != crashBatchSize {
			t.Fatalf("round %d: batch %d is partially applied: %d of %d entities", round, n, have, crashBatchSize)
		}
		if have == 0 {
			break
		}
		present++
	}
	if got := g.LiveCount(); got != present*crashBatchSize {
		t.Fatalf("round %d: %d live entities, want %d (%d batches); a later batch exists without its predecessor", round, got, present*crashBatchSize, present)
	}
	return present
}

var crashIDCache = map[int][]string{}

// crashIDs returns the entity IDs of the n-th Batch, computed once.
func crashIDs(t *testing.T, n int) []string {
	if ids, ok := crashIDCache[n]; ok {
		return ids
	}
	ids := make([]string, crashBatchSize)
	for i := range ids {
		id, err := ident.Hash("host", map[string]string{"hostname": crashHostName(n, i)})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	crashIDCache[n] = ids
	return ids
}
