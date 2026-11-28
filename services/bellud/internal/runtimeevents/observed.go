package runtimeevents

import (
	"net"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/coreschema"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
)

// SupportWindow is how recent an observation must be to support a computed path.
const SupportWindow = 24 * time.Hour

// Path marks (Requirement 12.8).
const (
	MarkSupported    = "supported"
	MarkContradicted = "contradicted"
)

// ObservedCollector names the batch source of observed_connection edges.
const ObservedCollector = "runtime"

// Observation is one observed connection between two entity ids.
type Observation struct {
	From, To string
	At       time.Time
}

// ConnectDest extracts the destination host from a network_connect event's
// args ("ip:port", "dst=ip:port" or "ip"). It returns "" when none is found.
func ConnectDest(args string) string {
	for _, f := range strings.Fields(args) {
		f = strings.TrimPrefix(strings.TrimPrefix(f, "dst="), "daddr=")
		if h, _, err := net.SplitHostPort(f); err == nil {
			f = h
		}
		if ip := net.ParseIP(strings.Trim(f, "[]")); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func sourceEntity(e wire.Event) (batch.Entity, bool) {
	if e.ContainerID != "" {
		return batch.Entity{Type: coreschema.KindContainer, Identity: map[string]string{"id": e.ContainerID}}, true
	}
	if e.Node != "" {
		return batch.Entity{Type: coreschema.KindHost, Identity: map[string]string{"hostname": e.Node}}, true
	}
	return batch.Entity{}, false
}

func entityID(en batch.Entity) (string, bool) {
	id, err := identity.Hash(en.Type, en.Identity)
	return string(id), err == nil
}

// ObservedBatch turns network_connect events into observed_connection edges
// from the source container or host to the destination host. Other events and
// events without a parsable destination are skipped. The batch retains all
// hosts and containers so it never retires entities other collectors own.
func ObservedBatch(events []wire.Event, now time.Time) (batch.Batch, []Observation) {
	b := batch.Batch{Collector: ObservedCollector, ObservedAt: now,
		Retain: []batch.Retain{{Kind: coreschema.KindHost}, {Kind: coreschema.KindContainer}}}
	var obs []Observation
	seen := map[string]bool{}
	for _, e := range events {
		if e.Type != wire.TypeNetworkConnect {
			continue
		}
		dst := ConnectDest(e.Args)
		src, ok := sourceEntity(e)
		if dst == "" || !ok {
			continue
		}
		to := batch.Entity{Type: coreschema.KindHost, Identity: map[string]string{"hostname": dst}}
		from, ok1 := entityID(src)
		toID, ok2 := entityID(to)
		if !ok1 || !ok2 || from == toID {
			continue
		}
		at := e.TS
		if at.IsZero() {
			at = now
		}
		for _, en := range []batch.Entity{src, to} {
			if id, _ := entityID(en); !seen[id] {
				seen[id] = true
				b.Entities = append(b.Entities, en)
			}
		}
		b.Relations = append(b.Relations, batch.Relation{Type: coreschema.RelObservedConnection, From: from, To: toID,
			Attributes: map[string]any{"evidence": truncate("runtime network_connect "+e.Args, 512),
				"confidence": "extracted", "observed_at": at.UTC().Format(time.RFC3339)}})
		obs = append(obs, Observation{From: from, To: toID, At: at})
	}
	return b, obs
}

// MarkPaths compares observations with computed paths, each given as a
// (from,to) pair. A computed path is supported when an observation of the same
// pair is within SupportWindow of now. An observation with no computed path is
// contradicted. The result maps "from->to" to a mark; computed paths with no
// recent observation are absent (unmarked).
func MarkPaths(computed [][2]string, obs []Observation, now time.Time) map[string]string {
	have := map[string]bool{}
	for _, p := range computed {
		have[p[0]+"->"+p[1]] = true
	}
	out := map[string]string{}
	for _, o := range obs {
		k := o.From + "->" + o.To
		switch {
		case !have[k]:
			out[k] = MarkContradicted
		case now.Sub(o.At) <= SupportWindow && !o.At.After(now.Add(maxSkew)):
			out[k] = MarkSupported
		}
	}
	return out
}

// ObservedHook returns an OnEvent callback that writes observed_connection
// edges. apply returns nil while no graph is ready, in which case events are
// skipped.
func ObservedHook(apply func() func(batch.Batch) error, onErr func(error)) func(wire.Event) {
	return func(e wire.Event) {
		if e.Type != wire.TypeNetworkConnect {
			return
		}
		fn := apply()
		if fn == nil {
			return
		}
		b, obs := ObservedBatch([]wire.Event{e}, time.Now())
		if len(obs) == 0 {
			return
		}
		if err := fn(b); err != nil && onErr != nil {
			onErr(err)
		}
	}
}
