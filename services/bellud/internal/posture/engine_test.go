package posture

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/facade"
)

type fakeReader struct{ n int }

func (f fakeReader) Entity(_ context.Context, id facade.EntityID, _ *time.Time) (facade.Entity, error) {
	return facade.Entity{ID: id, Type: "aws_resource", Attributes: map[string]any{"public": true}}, nil
}
func (f fakeReader) Find(context.Context, facade.FindQuery) (facade.Page[facade.Entity], error) {
	return facade.Page[facade.Entity]{Items: make([]facade.Entity, f.n)}, nil
}
func (f fakeReader) Neighbors(context.Context, facade.EntityID, facade.NeighborOpts) (facade.Page[facade.Edge], error) {
	return facade.Page[facade.Edge]{}, nil
}

func engineFor(t *testing.T, rules map[string]string) (*Engine, []RuleError) {
	t.Helper()
	fsys := fstest.MapFS{}
	var rs []Rule
	for id, src := range rules {
		fsys[id+".rego"] = &fstest.MapFile{Data: []byte(src)}
		rs = append(rs, Rule{ID: id, AppliesTo: []string{"aws_resource"}, Rego: id + ".rego"})
	}
	return NewEngine(context.Background(), []Pack{{ID: "p", Version: "1", Rules: rs, Source: fsys}}, fakeReader{n: 5})
}

const hdr = "package bellu.p.r\nimport rego.v1\n"

func eval(e *Engine) ([]Match, []EvalError) {
	return e.EvalEntity(context.Background(), Input{ID: "aws_resource:1", Type: "aws_resource", Attributes: map[string]any{"public": true}})
}

func TestSimpleRuleFires(t *testing.T) {
	e, errs := engineFor(t, map[string]string{"r": hdr + `violation contains {"discriminator": "d", "evidence": {"id": input.id}} if input.attributes.public`})
	m, ee := eval(e)
	if len(errs) != 0 || len(ee) != 0 || len(m) != 1 || m[0].Discriminator != "d" || m[0].Evidence["id"] != "aws_resource:1" {
		t.Fatalf("%+v %v %v", m, errs, ee)
	}
}

func TestHTTPSendRejectedAtCompile(t *testing.T) {
	e, errs := engineFor(t, map[string]string{"r": hdr + `violation contains {} if http.send({"method":"get","url":"http://x"})`})
	if len(errs) != 1 || errs[0].RuleID != "r" || len(e.rules) != 0 {
		t.Fatalf("%v", errs)
	}
	if CompileRego(context.Background(), hdr+`violation contains {} if opa.runtime()`) == nil {
		t.Fatal("opa.runtime compiled")
	}
}

func TestCPULimit(t *testing.T) {
	e, _ := engineFor(t, map[string]string{"r": hdr + `violation contains {} if { some i in numbers.range(1, 3000); some j in numbers.range(1, 3000); some k in numbers.range(1, 3000); i+j+k < 0 }`})
	start := time.Now()
	_, ee := eval(e)
	if len(ee) != 1 || ee[0].Limit != LimitCPU || time.Since(start) > 3*time.Second {
		t.Fatalf("%v %v", ee, time.Since(start))
	}
}

func TestMemoryBombStopped(t *testing.T) {
	e, errs := engineFor(t, map[string]string{"r": hdr + `violation contains {} if { s := {sprintf("%d-%d-%d", [i, j, k]) | some i in numbers.range(1, 400); some j in numbers.range(1, 400); some k in numbers.range(1, 400)}; count(s) < 0 }`})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	e.cpuLimit = time.Minute
	var peak atomic.Uint64
	stop := make(chan bool)
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
				runtime.ReadMemStats(&m)
				peak.Store(max(peak.Load(), m.HeapAlloc))
			}
		}
	}()
	_, ee := eval(e)
	close(stop)
	if len(ee) != 1 || ee[0].Limit != LimitMemory {
		t.Fatalf("%v", ee)
	}
	// stopped at the limit (256 MB plus a small margin), not after it
	if p := peak.Load(); p > MemoryLimitBytes+64<<20 {
		t.Fatalf("peak heap %d MB", p>>20)
	}
}

func TestQueryLimits(t *testing.T) {
	calls := hdr + `violation contains {} if { some i in numbers.range(1, 101); bellu.entity(input.id) }`
	find := hdr + `violation contains {} if { count(bellu.find("aws_resource", {})) > 0 }`
	e, _ := engineFor(t, map[string]string{"calls": calls, "find": find})
	_, ee := eval(e)
	got := map[string]Limit{}
	for _, x := range ee {
		got[x.RuleID] = x.Limit
	}
	if got["calls"] != LimitQueries || len(ee) != 1 { // find returns 5 entities: within limits
		t.Fatalf("%v", ee)
	}
	big := NewBigReaderEngine(t, find)
	if _, ee := eval(big); len(ee) != 1 || ee[0].Limit != LimitEntities {
		t.Fatalf("%v", ee)
	}
}

func NewBigReaderEngine(t *testing.T, src string) *Engine {
	e, _ := engineFor(t, map[string]string{"find": src})
	e.reader = bigReader{}
	return e
}

type bigReader struct{ fakeReader }

func (bigReader) Find(context.Context, facade.FindQuery) (facade.Page[facade.Entity], error) {
	return facade.Page[facade.Entity]{Items: make([]facade.Entity, 1000), Truncated: true}, nil
}

func TestOneRuleErrorDoesNotStopOthers(t *testing.T) {
	e, _ := engineFor(t, map[string]string{
		"a": hdr + `violation contains {} if { x := 1 / 0; x > 0 }`,
		"b": hdr + `violation contains {"discriminator": "ok"} if true`,
	})
	m, ee := eval(e)
	if len(ee) != 1 || ee[0].RuleID != "a" || len(m) != 1 || m[0].RuleID != "b" {
		t.Fatalf("%+v %v", m, ee)
	}
}

func TestLoaderCompilesRego(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"id": "p", "version": "1", "rules": []map[string]any{okRule()}})
	fsys := fstest.MapFS{"p/pack.json": {Data: b}, "p/r1.rego": {Data: []byte("package bellu.p.r1\nviolation contains {} if http.send({})\n")}}
	_, errs, _ := LoadAll(fsys)
	if len(errs) != 1 || errs[0].Check != "compile" || !strings.Contains(errs[0].Detail, "http.send") && !strings.Contains(errs[0].Detail, "unsafe") {
		t.Fatalf("%v", errs)
	}
}
