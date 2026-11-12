//go:build !linux

package host

import (
	"context"
	"testing"
	"time"
)

func TestNonLinuxNoOp(t *testing.T) {
	b, err := New(time.Second).Collect(context.Background())
	if err != nil || b.Collector != Name || len(b.Entities) != 0 || len(b.Relations) != 0 {
		t.Fatalf("got %+v, %v", b, err)
	}
}
