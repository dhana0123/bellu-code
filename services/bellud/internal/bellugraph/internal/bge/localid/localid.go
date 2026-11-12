// Package localid maps entity IDs to short, session-friendly aliases of the
// form "@abc234". Aliases expire after an idle period and stay reserved as
// tombstones so a retired alias is never handed to a different entity.
package localid

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

const (
	// DefaultIdle is the idle time after which an alias is retired.
	DefaultIdle = 15 * time.Minute
	// DefaultTombstone is how long a retired alias stays reserved.
	DefaultTombstone = 24 * time.Hour

	alphabet = "23456789abcdefghijkmnpqrstuvwxyz"
	idLen    = 6
)

type live struct {
	id   string
	last time.Time
}

// Registry is a concurrency-safe alias registry.
type Registry struct {
	clock     func() time.Time
	idle      time.Duration
	tombstone time.Duration

	mu     sync.Mutex
	alias  map[string]*live     // alias -> live entry
	byID   map[string]string    // entity -> live alias
	retire map[string]time.Time // alias -> retirement time
}

// New builds a Registry. A nil clock uses time.Now.
func New(clock func() time.Time, idle, tombstone time.Duration) *Registry {
	if clock == nil {
		clock = time.Now
	}
	return &Registry{
		clock:     clock,
		idle:      idle,
		tombstone: tombstone,
		alias:     map[string]*live{},
		byID:      map[string]string{},
		retire:    map[string]time.Time{},
	}
}

// For returns the live alias of id, refreshing it, or mints a new one.
func (r *Registry) For(id string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	if a, ok := r.byID[id]; ok {
		if e := r.alias[a]; now.Sub(e.last) < r.idle {
			e.last = now
			return a
		}
		r.retireLocked(a, now)
	}
	a := r.mintLocked(now)
	r.alias[a] = &live{id: id, last: now}
	r.byID[id] = a
	return a
}

// Lookup resolves an alias and refreshes it. Retired or unknown aliases yield
// errs.NotFound.
func (r *Registry) Lookup(alias string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	e, ok := r.alias[alias]
	if ok && now.Sub(e.last) >= r.idle {
		r.retireLocked(alias, now)
		ok = false
	}
	if !ok {
		return "", fmt.Errorf("%w: local id %q is unknown or expired; use the identity_fingerprint instead", errs.NotFound, alias)
	}
	e.last = now
	return e.id, nil
}

// Sweep retires idle aliases and drops tombstones older than the tombstone
// period.
func (r *Registry) Sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	for a, e := range r.alias {
		if now.Sub(e.last) >= r.idle {
			r.retireLocked(a, now)
		}
	}
	for a, t := range r.retire {
		if now.Sub(t) >= r.tombstone {
			delete(r.retire, a)
		}
	}
}

func (r *Registry) retireLocked(a string, now time.Time) {
	e := r.alias[a]
	delete(r.alias, a)
	if r.byID[e.id] == a {
		delete(r.byID, e.id)
	}
	r.retire[a] = now
}

// mintLocked draws random aliases until one is neither live nor tombstoned.
func (r *Registry) mintLocked(now time.Time) string {
	for {
		a := randomAlias()
		if _, ok := r.alias[a]; ok {
			continue
		}
		if t, ok := r.retire[a]; ok {
			if now.Sub(t) < r.tombstone {
				continue
			}
			delete(r.retire, a)
		}
		return a
	}
}

func randomAlias() string {
	var raw [idLen]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	out := make([]byte, 0, idLen+1)
	out = append(out, '@')
	for _, b := range raw {
		// 256 is a multiple of the 32-letter alphabet, so no modulo bias.
		out = append(out, alphabet[int(b)%len(alphabet)])
	}
	return string(out)
}
