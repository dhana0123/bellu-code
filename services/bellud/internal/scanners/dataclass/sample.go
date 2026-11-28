package dataclass

import (
	"context"
	"fmt"
	"sort"

	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

// SampleObjectBytes caps the bytes read from one object (13.4).
const SampleObjectBytes = 64 * 1024

// ObjectReader reads sampled S3 objects through the AWS connector broker with
// read-only calls (aws.ObjectSampler has this method).
type ObjectReader interface {
	SampleObjects(ctx context.Context, bucket, region string, limit, maxBytes int, fn func(content []byte)) error
}

// Sampling is the opt-in content sampling setup. The zero value is off.
// Only S3 buckets are sampled; RDS and DynamoDB sampling is a known gap.
type Sampling struct {
	Reader ObjectReader
	Limit  int             // data.sample_limit, 1 to 10,000
	Stores map[string]bool // data.sample_stores: Entity_IDs that opted in
}

// WithSampling returns a copy of a that samples the opted-in stores.
func (a Adapter) WithSampling(s Sampling) Adapter { a.sample = s; return a }

// run samples one store. It returns nil counts (and no error) when sampling
// does not apply: off, not opted in, or not an S3 bucket.
func (s Sampling) run(ctx context.Context, pats Patterns, st Store) (map[string]int, error) {
	if s.Reader == nil || s.Limit < 1 || !s.Stores[st.ID] || st.Type != "s3:bucket" {
		return nil, nil
	}
	counts := map[string]int{}
	err := s.Reader.SampleObjects(ctx, st.Name, st.Region, s.Limit, SampleObjectBytes, func(content []byte) {
		pats.CountMatches(content, counts) // classified in memory; content is dropped here
	})
	if err != nil {
		msg, rerr := redact.Text(err.Error())
		if rerr != nil {
			msg = redact.FailedPlaceholder
		}
		return nil, fmt.Errorf("sampling %s: %s", st.ID, msg)
	}
	for c, n := range counts {
		if n == 0 {
			delete(counts, c)
		}
	}
	return counts, nil
}

// mergeClasses adds the classes found by sampling to the metadata classes.
func mergeClasses(classes []string, counts map[string]int) []string {
	set := map[string]struct{}{}
	for _, c := range classes {
		if c != ClassNone {
			set[c] = struct{}{}
		}
	}
	for c := range counts {
		set[c] = struct{}{}
	}
	if len(set) == 0 {
		return []string{ClassNone}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
