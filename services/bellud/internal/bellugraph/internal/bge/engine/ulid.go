package engine

import (
	"bytes"
	crand "crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// ulidGen hands out strictly increasing ULIDs. Callers hold applyMu.
type ulidGen struct {
	entropy *ulid.MonotonicEntropy
	last    ulid.ULID
}

func (g *ulidGen) next(t time.Time) ulid.ULID {
	if g.entropy == nil {
		g.entropy = ulid.Monotonic(crand.Reader, 0)
	}
	id, err := ulid.New(ulid.Timestamp(t), g.entropy)
	if err != nil || bytes.Compare(id[:], g.last[:]) <= 0 {
		// Clock regression or entropy trouble: step past the previous ID.
		id = g.last
		for i := len(id) - 1; i >= 0; i-- {
			id[i]++
			if id[i] != 0 {
				break
			}
		}
	}
	g.last = id
	return id
}
