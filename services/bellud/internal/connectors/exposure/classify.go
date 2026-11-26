package exposure

import (
	"net/netip"
	"slices"
	"sort"
)

// Path is one network path to a resource.
type Path struct {
	Confirmed bool     // only confirmed (extracted) paths count
	Origin    string   // source CIDR, e.g. 0.0.0.0/0; empty when InAccount
	InAccount bool     // the source is an entity inside the account
	Evidence  []string // Entity_IDs of the rule, route or gateway that make the path
}

// Classify is total over paths. It returns internet when a confirmed path
// with evidence originates from 0.0.0.0/0 or ::/0, internal when it is not
// internet and every confirmed path originates from a private range or an
// in-account entity, and unknown otherwise (no confirmed path, or a path whose
// origin cannot be shown to be private). Internet results carry the evidence
// of every internet path, sorted and deduplicated.
func Classify(paths []Path) Exposure {
	var evidence []string
	allInternal, confirmed := true, 0
	for _, p := range paths {
		if !p.Confirmed {
			continue
		}
		confirmed++
		switch {
		case isOpenOrigin(p.Origin) && len(p.Evidence) > 0:
			evidence = append(evidence, p.Evidence...)
		case !p.InAccount && !isPrivateOrigin(p.Origin):
			allInternal = false
		}
	}
	if len(evidence) > 0 {
		sort.Strings(evidence)
		return Exposure{Value: Internet, Evidence: slices.Compact(evidence)}
	}
	if confirmed > 0 && allInternal {
		return Exposure{Value: Internal}
	}
	return Exposure{Value: Unknown}
}

func isOpenOrigin(origin string) bool {
	p, err := netip.ParsePrefix(origin)
	return err == nil && p.Bits() == 0
}

func isPrivateOrigin(origin string) bool {
	p, err := netip.ParsePrefix(origin)
	return err == nil && p.Bits() > 0 && p.Addr().IsPrivate()
}
