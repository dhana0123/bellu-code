package cveupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bellu/global-cv-graph/pkg/sign"
	"pgregory.net/rapid"
)

// Feature: bellu-three-graph-security-intelligence, Property 40: Update
// verifies checksum and signature, and is atomic.
//
// **Validates: Requirements 19.1, 19.5, 19.10, 19.11**
//
// Every iteration installs snapshot 3, then attempts an update with one
// generated fault (or none) while a reader polls cve/current. A failed update
// must leave current, state.json and the snapshot set as they were, remove
// staging, append exactly one failure audit row and name the failing step. A
// successful update must be visible only as old or new, never as a mixture.

type faultCase struct {
	name string
	// step is the InstallError.Step expected for a failure; "" for success.
	step string
}

var faultCases = []faultCase{
	{"none", ""},
	{"checksum", StepVerify},
	{"signature", StepVerify},
	{"flipped-byte", StepVerify},
	{"truncated-body", StepDownload},
	{"missing-pack", StepDownload},
	{"cancelled", StepDownload},
	{"schema-mismatch", StepIntegrity},
	{"integrity", StepIntegrity},
	{"disk-space", StepDisk},
	{"downgrade", StepPlan},
	{"downgrade-allowed", ""},
	{"inject-download", StepDownload},
	{"inject-verify", StepVerify},
	{"inject-apply", StepApply},
	{"inject-swap", StepSwap},
	{"crash-download", ""},
	{"crash-verify", ""},
	{"crash-apply", ""},
	{"crash-swap", ""},
}

type crashSignal struct{}

// pollCurrent reads cve/current in a loop and records the first observation
// that is not one of the allowed snapshot ids or whose database is unreadable.
func pollCurrent(dir string, allowed ...string) (stop func() string) {
	var (
		done      = make(chan struct{})
		wg        sync.WaitGroup
		violation atomic.Value
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			l, err := os.Readlink(filepath.Join(dir, "current"))
			if err != nil {
				violation.CompareAndSwap(nil, "readlink: "+err.Error())
				continue
			}
			id := filepath.Base(l)
			ok := false
			for _, a := range allowed {
				ok = ok || id == a
			}
			if !ok {
				violation.CompareAndSwap(nil, "reader saw unexpected snapshot "+id)
			}
			if _, err := os.Stat(filepath.Join(dir, "current", "graph.db")); err != nil {
				violation.CompareAndSwap(nil, "current/graph.db unreadable: "+err.Error())
			}
		}
	}()
	return func() string {
		close(done)
		wg.Wait()
		if v, _ := violation.Load().(string); v != "" {
			return v
		}
		return ""
	}
}

func snapshotNames(dir string) []string {
	ents, _ := os.ReadDir(filepath.Join(dir, "snapshots"))
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	return names
}

func TestUpdateVerifiesAndIsAtomicProperty(t *testing.T) {
	e := newEnv(t) // one server and key for all iterations
	packs := map[int][]byte{}
	for _, d := range []int{2, 3, 4} {
		packs[d] = snapshotPack(t, d, "1", false)
	}
	badSchema := snapshotPack(t, 4, "99", false)
	corrupt := snapshotPack(t, 4, "1", true)
	_, otherKey, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := tsnap(2)
	id3, _ := tsnap(3)
	id4, _ := tsnap(4)

	rapid.Check(t, func(rt *rapid.T) {
		fc := rapid.SampledFrom(faultCases).Draw(rt, "fault")
		flipSeed := rapid.Uint32().Draw(rt, "flipSeed")
		cutSeed := rapid.Uint32().Draw(rt, "cutSeed")

		e.dir = filepath.Join(t.TempDir(), "cve")
		e.audit = &memAudit{}
		e.up.Dir, e.up.Audit = e.dir, e.audit
		e.up.AfterStep, e.up.FreeBytes, e.up.AllowDowngrade = nil, nil, false

		ctx := context.Background()
		base := e.snap(3, packs[3])
		if _, err := e.up.InstallIndex(ctx, &Index{Latest: base, Snapshots: []Snapshot{base}}); err != nil {
			rt.Fatalf("baseline install: %v", err)
		}
		before, state, snaps := e.currentID(), e.stateBytes(), snapshotNames(e.dir)
		if before != id3 {
			rt.Fatalf("baseline current %s, want %s", before, id3)
		}

		// Build the offered index.
		day, data := 4, packs[4]
		switch fc.name {
		case "schema-mismatch":
			data = badSchema
		case "integrity":
			data = corrupt
		case "downgrade", "downgrade-allowed":
			day, data = 2, packs[2]
		}
		target := e.snap(day, data)
		newID := map[int]string{2: id2, 4: id4}[day]
		idx := &Index{Latest: target, Snapshots: []Snapshot{target}}
		crash, injectStep := strings.HasPrefix(fc.name, "crash-"), ""
		switch fc.name {
		case "checksum":
			idx.Latest.SHA256 = strings.Repeat("0", 64)
		case "signature":
			e.objects[target.URL+".sig"] = sign.Sign(otherKey, data)
		case "flipped-byte":
			b := append([]byte(nil), data...)
			b[int(flipSeed)%len(b)] ^= 0xff
			e.objects[target.URL] = b
		case "truncated-body":
			e.objects[target.URL] = data[:1+int(cutSeed)%(len(data)-1)]
		case "missing-pack":
			delete(e.objects, target.URL)
		case "cancelled":
			c, cancel := context.WithCancel(ctx)
			cancel()
			ctx = c
		case "disk-space":
			e.up.FreeBytes = func(string) (uint64, error) { return 10, nil }
		case "downgrade-allowed":
			e.up.AllowDowngrade = true
		}
		if strings.HasPrefix(fc.name, "inject-") {
			injectStep = strings.TrimPrefix(fc.name, "inject-")
		}
		if crash {
			injectStep = strings.TrimPrefix(fc.name, "crash-")
		}
		if injectStep != "" {
			e.up.AfterStep = func(s string) error {
				if s != injectStep {
					return nil
				}
				if crash {
					panic(crashSignal{})
				}
				return errors.New("injected failure")
			}
		}

		stop := pollCurrent(e.dir, id3, newID)
		var runErr error
		crashed := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(crashSignal); !ok {
						panic(r)
					}
					crashed = true
				}
			}()
			_, runErr = e.up.InstallIndex(ctx, idx)
		}()
		if v := stop(); v != "" {
			rt.Fatalf("%s: %s", fc.name, v)
		}

		failed := crashed || runErr != nil
		if fc.step == "" && !crash {
			// Success: readers moved from old to new in one step.
			if runErr != nil {
				rt.Fatalf("%s: unexpected failure: %v", fc.name, runErr)
			}
			if e.currentID() != newID || !strings.Contains(e.stateBytes(), newID) {
				rt.Fatalf("%s: current %s, want %s", fc.name, e.currentID(), newID)
			}
			if n := len(snapshotNames(e.dir)); n > 2 {
				rt.Fatalf("%s: %d snapshots kept", fc.name, n)
			}
			if r := e.audit.rows; len(r) != 2 || r[1].Outcome != "success" || r[1].FromID != id3 || r[1].ToID != newID {
				rt.Fatalf("%s: audit rows %+v", fc.name, r)
			}
			return
		}

		// Failure or crash: nothing visible changed.
		if !failed {
			rt.Fatalf("%s: expected failure", fc.name)
		}
		if e.currentID() != before || e.stateBytes() != state {
			rt.Fatalf("%s: current %s or state.json changed", fc.name, e.currentID())
		}
		if got := snapshotNames(e.dir); strings.Join(got, ",") != strings.Join(snaps, ",") {
			rt.Fatalf("%s: snapshot set changed: %v -> %v", fc.name, snaps, got)
		}
		if _, err := os.Stat(filepath.Join(e.dir, "current", "graph.db")); err != nil {
			rt.Fatalf("%s: old snapshot unreadable: %v", fc.name, err)
		}
		if !crashed {
			var ie *InstallError
			if !errors.As(runErr, &ie) || ie.Step != fc.step {
				rt.Fatalf("%s: error %v, want step %s", fc.name, runErr, fc.step)
			}
			if ents, _ := os.ReadDir(filepath.Join(e.dir, "staging")); len(ents) != 0 {
				rt.Fatalf("%s: staging not removed: %v", fc.name, ents)
			}
			if r := e.audit.rows; len(r) != 2 || r[1].Outcome != "failure" || r[1].Step != fc.step || r[1].Cause == "" {
				rt.Fatalf("%s: audit rows %+v", fc.name, r)
			}
			return
		}

		// A crash leaves staging behind; the next run cleans it and installs.
		if err := os.MkdirAll(filepath.Join(e.dir, "staging", "run-crashed", "work"), 0o755); err != nil {
			rt.Fatal(err)
		}
		e.up.AfterStep = nil
		fresh := e.snap(4, packs[4])
		if _, err := e.up.InstallIndex(context.Background(), &Index{Latest: fresh, Snapshots: []Snapshot{fresh}}); err != nil {
			rt.Fatalf("%s: recovery install: %v", fc.name, err)
		}
		if e.currentID() != id4 {
			rt.Fatalf("%s: after recovery current %s, want %s", fc.name, e.currentID(), id4)
		}
		if ents, _ := os.ReadDir(filepath.Join(e.dir, "staging")); len(ents) != 0 {
			rt.Fatalf("%s: staging left after recovery: %v", fc.name, ents)
		}
	})
}
