package connectors

import (
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
)

// Resolver resolves an agent-supplied connection reference (id first, then
// alias) to a broker reference. It implements the connector MCP Resolver.
type Resolver struct{ svc *Service }

// NewResolver returns the Resolver of svc.
func NewResolver(svc *Service) *Resolver { return &Resolver{svc: svc} }

// ResolveConnection finds a live connection by exact id, else by alias
// (case-insensitive). An alias shared by several connections is ambiguous and
// resolves to nothing, so an agent can never read the wrong account.
func (r *Resolver) ResolveConnection(ref string) (broker.ConnectionRef, bool) {
	if r == nil || !r.svc.Enabled() || strings.TrimSpace(ref) == "" {
		return broker.ConnectionRef{}, false
	}
	id, ok := "", false
	if c, found := r.svc.Connection(ref); found {
		id, ok = c.ID, true
	} else {
		for _, c := range r.svc.Connections() {
			if !strings.EqualFold(c.Alias, ref) {
				continue
			}
			if ok {
				return broker.ConnectionRef{}, false
			}
			id, ok = c.ID, true
		}
	}
	if !ok {
		return broker.ConnectionRef{}, false
	}
	cr, err := r.svc.BrokerRef(id)
	return cr, err == nil
}
