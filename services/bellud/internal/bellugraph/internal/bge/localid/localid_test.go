package localid

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newReg() (*Registry, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return New(c.now, DefaultIdle, DefaultTombstone), c
}

func TestFormatAndStability(t *testing.T) {
	r, _ := newReg()
	re := regexp.MustCompile(`^@[23456789a-km-np-z]{6}$`)
	a := r.For("e1")
	if !re.MatchString(a) {
		t.Fatalf("bad alias %q", a)
	}
	if r.For("e1") != a {
		t.Fatal("alias not stable")
	}
	if r.For("e2") == a {
		t.Fatal("alias collision")
	}
	if strings.ContainsAny(a, "l01o") {
		t.Fatalf("forbidden char in %q", a)
	}
}

func TestLookupRefreshesAndExpires(t *testing.T) {
	r, c := newReg()
	a := r.For("e1")
	c.advance(14 * time.Minute)
	if id, err := r.Lookup(a); err != nil || id != "e1" {
		t.Fatalf("lookup: %v %v", id, err)
	}
	c.advance(14 * time.Minute) // refreshed, still live
	if _, err := r.Lookup(a); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	c.advance(15 * time.Minute)
	r.Sweep()
	_, err := r.Lookup(a)
	if !errors.Is(err, errs.NotFound) || !strings.Contains(err.Error(), "identity_fingerprint") {
		t.Fatalf("want NotFound mentioning identity_fingerprint, got %v", err)
	}
	if _, err := r.Lookup("@zzzzzz"); !errors.Is(err, errs.NotFound) {
		t.Fatalf("unknown alias: %v", err)
	}
}

func TestRetiredAliasNotReusedWithinTombstone(t *testing.T) {
	r, c := newReg()
	old := r.For("e1")
	c.advance(DefaultIdle)
	r.Sweep()
	if r.For("e1") == old {
		t.Fatal("retired alias reissued within tombstone")
	}
	if _, ok := r.retire[old]; !ok {
		t.Fatal("tombstone missing")
	}
	c.advance(DefaultTombstone)
	r.Sweep()
	if _, ok := r.retire[old]; ok {
		t.Fatal("tombstone not purged")
	}
}

func TestConcurrent(t *testing.T) {
	r, _ := newReg()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				a := r.For("e")
				if _, err := r.Lookup(a); err != nil {
					t.Error(err)
					return
				}
				r.Sweep()
			}
		}()
	}
	wg.Wait()
}
