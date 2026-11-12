package engine

import (
	"context"
	"fmt"
	"regexp"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/codec"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

const (
	maxAnnotationKeys  = 64
	maxAnnotationValue = 1024
)

var annotationKey = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

// Annotations is a read view over the operator-owned annotations.
type Annotations struct{ c *Core }

// Get returns the annotation of entity id, if it has one.
func (a *Annotations) Get(id string) (Annotation, bool, error) {
	if err := a.c.readable(); err != nil {
		return Annotation{}, false, err
	}
	a.c.mu.RLock()
	defer a.c.mu.RUnlock()
	an, ok := a.c.g.Annotation(id)
	return an, ok, nil
}

// Count returns the number of entities that carry annotations.
func (a *Annotations) Count() (int, error) {
	if err := a.c.readable(); err != nil {
		return 0, err
	}
	a.c.mu.RLock()
	defer a.c.mu.RUnlock()
	return a.c.g.AnnotationCount(), nil
}

// readable reports ErrUnavailable once the Engine is closed or failed.
func (c *Core) readable() error {
	switch s := c.State(); s {
	case StateClosed, StateFailed:
		return fmt.Errorf("%w: graph engine is %s", errs.Unavailable, s)
	}
	return nil
}

// Annotate sets and removes operator annotations on a live entity and returns
// the resulting annotation. Collector Batches never touch annotations. A call
// that changes nothing appends nothing.
func (c *Core) Annotate(ctx context.Context, id string, set map[string]string, unset []string, actor string) (Annotation, error) {
	if err := ctx.Err(); err != nil {
		return Annotation{}, err
	}
	if err := c.writable(); err != nil {
		c.met.BatchRejected("unavailable")
		return Annotation{}, err
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if err := c.writable(); err != nil {
		c.met.BatchRejected("unavailable")
		return Annotation{}, err
	}

	c.mu.RLock()
	es, ok := c.g.Entity(id)
	live := ok && es.Live
	cur, _ := c.g.Annotation(id)
	c.mu.RUnlock()
	if !live {
		return Annotation{}, fmt.Errorf("%w: entity %q", errs.NotFound, id)
	}
	next, err := applyAnnotation(cur.Values, set, unset)
	if err != nil {
		c.met.BatchRejected("validation")
		return Annotation{}, err
	}
	if sameStrings(cur.Values, next) {
		return cur, nil
	}

	ev := codec.Event{Type: codec.Annotated, ID: id, Actor: actor, AnnoSet: set, Unset: unset}
	if _, err := c.commit([]codec.Event{ev}, c.clock().UTC()); err != nil {
		c.met.BatchRejected("store")
		c.log.Error("graph annotation rejected: store write failed", "error", err.Error())
		return Annotation{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	an, _ := c.g.Annotation(id)
	if an.Values == nil {
		an.Values = map[string]string{}
	}
	return an, nil
}

// applyAnnotation validates a change and returns the resulting values.
func applyAnnotation(cur, set map[string]string, unset []string) (map[string]string, error) {
	next := make(map[string]string, len(cur)+len(set))
	for k, v := range cur {
		next[k] = v
	}
	for k, v := range set {
		if !annotationKey.MatchString(k) {
			return nil, fmt.Errorf("%w: annotation key %q must match [a-z0-9_.-]{1,64}", errs.Validation, k)
		}
		if len(v) > maxAnnotationValue {
			return nil, fmt.Errorf("%w: annotation %q value exceeds %d bytes", errs.Validation, k, maxAnnotationValue)
		}
		next[k] = v
	}
	for _, k := range unset {
		if !annotationKey.MatchString(k) {
			return nil, fmt.Errorf("%w: annotation key %q must match [a-z0-9_.-]{1,64}", errs.Validation, k)
		}
		if _, both := set[k]; both {
			return nil, fmt.Errorf("%w: annotation key %q is both set and removed", errs.Validation, k)
		}
		delete(next, k)
	}
	if len(next) > maxAnnotationKeys {
		return nil, fmt.Errorf("%w: an entity takes at most %d annotations", errs.Validation, maxAnnotationKeys)
	}
	return next, nil
}

func sameStrings(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
