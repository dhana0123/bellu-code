package bom

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
)

// ecosystemProperty carries Package.Ecosystem through a CycloneDX document.
const ecosystemProperty = "bellu:ecosystem"

var purlTypePattern = regexp.MustCompile(`^pkg:[a-z][a-z0-9.+-]*/.`)

// Options configures Write. The zero value writes CycloneDX 1.6 with the
// current time and a random serial number.
type Options struct {
	Format  Format
	Version string
	// Now and Serial can be set in tests to fix timestamp and serialNumber.
	Now    func() time.Time
	Serial func() string
}

// Write exports s to w in CycloneDX JSON (the default) or SPDX JSON. It validates the request and every package before the
// first byte is written, so an error from validation leaves w untouched.
// Components are encoded one at a time, so memory use does not grow with the
// size of the output.
func Write(ctx context.Context, w io.Writer, s SBOM, opts Options) error {
	if opts.Format == "" {
		opts.Format = FormatCycloneDXJSON
	}
	if _, ok := supported[opts.Format]; !ok {
		return unsupportedFormat(opts.Format)
	}
	if opts.Version == "" {
		opts.Version = DefaultCycloneDXVersion
		if opts.Format == FormatSPDXJSON {
			opts.Version = DefaultSPDXVersion
		}
	}
	if !versionSupported(opts.Format, opts.Version) {
		return unsupportedVersion(opts.Format, opts.Version)
	}
	if opts.Format == FormatSPDXJSON {
		return writeSPDX(ctx, w, s, opts)
	}
	return writeCycloneDX(ctx, w, s, opts)
}

type prepared struct {
	pkg  *Package
	typ  string
	purl string
	tie  string // canonical form of the remaining fields, so the sort is total
}

// prepareItems validates every package and returns them in export order. It
// is shared by the CycloneDX and SPDX writers.
func prepareItems(s SBOM) ([]prepared, error) {
	items := make([]prepared, len(s.Packages))
	for i := range s.Packages {
		p := &s.Packages[i]
		it := prepared{pkg: p, typ: p.Type}
		if it.typ == "" {
			it.typ = string(cdx.ComponentTypeLibrary)
		}
		if p.Purl != nil {
			purl, ok := canonicalPurl(*p.Purl)
			if !ok {
				return nil, fmt.Errorf("%w: %q has an invalid purl %q", ErrInvalidPackage, p.Name, *p.Purl)
			}
			it.purl = purl
		} else if knownEcosystems[p.Ecosystem] {
			return nil, fmt.Errorf("%w: %q has ecosystem %q but no purl", ErrInvalidPackage, p.Name, p.Ecosystem)
		}
		it.tie = tieKey(p)
		items[i] = it
	}
	sort.SliceStable(items, func(a, b int) bool {
		x, y := items[a], items[b]
		if x.typ != y.typ {
			return x.typ < y.typ
		}
		if x.pkg.Name != y.pkg.Name {
			return x.pkg.Name < y.pkg.Name
		}
		if xv, yv := deref(x.pkg.Version), deref(y.pkg.Version); xv != yv {
			return xv < yv
		}
		if x.purl != y.purl {
			return x.purl < y.purl
		}
		return x.tie < y.tie
	})
	return items, nil
}

// tieKey encodes the fields not covered by the primary sort keys, with lists
// and maps in sorted order, so packages equal on those keys sort the same way
// whatever the input order.
func tieKey(p *Package) string {
	hashes := make([]string, len(p.Hashes))
	for i, h := range p.Hashes {
		hashes[i] = h.Algorithm + "=" + h.Value
	}
	props := make([]string, 0, len(p.Properties))
	for k, v := range p.Properties {
		props = append(props, k+"="+v)
	}
	sup := "\x00"
	if p.Supplier != nil {
		sup = "\x01" + *p.Supplier
	}
	return strings.Join([]string{
		strings.Join(sortedUnique(p.Locations), "\x02"),
		p.Ecosystem,
		sup,
		strings.Join(sortedUnique(p.Licenses), "\x02"),
		strings.Join(sortedUnique(hashes), "\x02"),
		strings.Join(sortedUnique(props), "\x02"),
	}, "\x03")
}

func writeCycloneDX(ctx context.Context, w io.Writer, s SBOM, opts Options) error {
	items, err := prepareItems(s)
	if err != nil {
		return err
	}

	now, serial := opts.Now, opts.Serial
	if now == nil {
		now = time.Now
	}
	if serial == nil {
		serial = newSerial
	}
	meta := cdx.Metadata{
		Timestamp: now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{
			{Type: cdx.ComponentTypeApplication, Name: "bellud"},
		}},
	}
	if s.Subject != "" {
		meta.Component = &cdx.Component{BOMRef: "bellu:subject", Type: cdx.ComponentTypeApplication, Name: s.Subject}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	versionJSON, _ := json.Marshal(opts.Version)
	serialJSON, _ := json.Marshal(serial())

	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, `{"$schema":"http://cyclonedx.org/schema/bom-%s.schema.json","bomFormat":"CycloneDX","specVersion":%s,"serialNumber":%s,"version":1,"metadata":%s,"components":[`,
		opts.Version, versionJSON, serialJSON, metaJSON)
	seen := make(map[string]int, len(items))
	for i, it := range items {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		c := toComponent(it, seen)
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if i > 0 {
			bw.WriteByte(',')
		}
		bw.WriteByte('\n')
		bw.Write(b)
	}
	if len(items) > 0 {
		bw.WriteByte('\n')
	}
	bw.WriteString("]}\n")
	return bw.Flush()
}

func toComponent(it prepared, seen map[string]int) cdx.Component {
	p := it.pkg
	c := cdx.Component{
		Type:       cdx.ComponentType(it.typ),
		Name:       p.Name,
		Version:    deref(p.Version),
		PackageURL: it.purl,
	}
	ref := it.purl
	if ref == "" {
		sum := sha256.Sum256([]byte(it.typ + "\x00" + p.Name + "\x00" + deref(p.Version)))
		ref = "bellu:" + hex.EncodeToString(sum[:8])
	}
	// Equal refs get a suffix in sorted order, so they stay stable between runs.
	if seen[ref]++; seen[ref] > 1 {
		ref = fmt.Sprintf("%s#%d", ref, seen[ref])
	}
	c.BOMRef = ref
	if p.Supplier != nil {
		c.Supplier = &cdx.OrganizationalEntity{Name: *p.Supplier}
	}
	if lic := sortedUnique(p.Licenses); len(lic) > 0 {
		l := make(cdx.Licenses, len(lic))
		for i, id := range lic {
			l[i] = cdx.LicenseChoice{License: &cdx.License{Name: id}}
		}
		if len(lic) == 1 && strings.ContainsAny(lic[0], " ()") {
			l = cdx.Licenses{{Expression: lic[0]}}
		}
		c.Licenses = &l
	}
	if len(p.Hashes) > 0 {
		h := make([]cdx.Hash, len(p.Hashes))
		for i, x := range p.Hashes {
			h[i] = cdx.Hash{Algorithm: cdx.HashAlgorithm(x.Algorithm), Value: x.Value}
		}
		sort.Slice(h, func(a, b int) bool {
			if h[a].Algorithm != h[b].Algorithm {
				return h[a].Algorithm < h[b].Algorithm
			}
			return h[a].Value < h[b].Value
		})
		c.Hashes = &h
	}
	if loc := sortedUnique(p.Locations); len(loc) > 0 {
		occ := make([]cdx.EvidenceOccurrence, len(loc))
		for i, l := range loc {
			occ[i] = cdx.EvidenceOccurrence{Location: l}
		}
		c.Evidence = &cdx.Evidence{Occurrences: &occ}
	}
	props := make([]cdx.Property, 0, len(p.Properties)+1)
	for k, v := range p.Properties {
		props = append(props, cdx.Property{Name: k, Value: v})
	}
	if p.Ecosystem != "" {
		props = append(props, cdx.Property{Name: ecosystemProperty, Value: p.Ecosystem})
	}
	if len(props) > 0 {
		sort.Slice(props, func(a, b int) bool {
			if props[a].Name != props[b].Name {
				return props[a].Name < props[b].Name
			}
			return props[a].Value < props[b].Value
		})
		c.Properties = &props
	}
	return c
}

// canonicalPurl normalizes the package part with canonical.Key and keeps the
// qualifiers and subpath, which Key drops.
func canonicalPurl(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	key, ok := canonical.Key(canonical.KindPurl, raw)
	if !ok || !purlTypePattern.MatchString(key) {
		return "", false
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		key += raw[i:]
	}
	return key, true
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	n := 0
	for i, s := range out {
		if i == 0 || s != out[n-1] {
			out[n] = s
			n++
		}
	}
	return out[:n]
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func newSerial() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return "urn:uuid:" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ReadCycloneDX parses a CycloneDX JSON document of version 1.5 or later.
func ReadCycloneDX(r io.Reader) (SBOM, error) {
	var doc cdx.BOM
	if err := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON).Decode(&doc); err != nil {
		return SBOM{}, fmt.Errorf("bom: parse cyclonedx: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return SBOM{}, fmt.Errorf("bom: parse cyclonedx: bomFormat is %q", doc.BOMFormat)
	}
	if doc.SpecVersion < cdx.SpecVersion1_5 {
		return SBOM{}, fmt.Errorf("%w %q for %s; supported: %s", ErrUnsupportedVersion, doc.SpecVersion, FormatCycloneDXJSON, strings.Join(supported[FormatCycloneDXJSON], ", "))
	}
	var out SBOM
	if doc.Metadata != nil && doc.Metadata.Component != nil {
		out.Subject = doc.Metadata.Component.Name
	}
	if doc.Components != nil {
		out.Packages = make([]Package, 0, len(*doc.Components))
		for _, c := range *doc.Components {
			out.Packages = append(out.Packages, fromComponent(c))
		}
	}
	return out, nil
}

func fromComponent(c cdx.Component) Package {
	p := Package{Type: string(c.Type), Name: c.Name, Version: strPtr(c.Version), Purl: strPtr(c.PackageURL)}
	if c.Supplier != nil {
		p.Supplier = strPtr(c.Supplier.Name)
	}
	if c.Licenses != nil {
		for _, l := range *c.Licenses {
			switch {
			case l.Expression != "":
				p.Licenses = append(p.Licenses, l.Expression)
			case l.License != nil && l.License.ID != "":
				p.Licenses = append(p.Licenses, l.License.ID)
			case l.License != nil && l.License.Name != "":
				p.Licenses = append(p.Licenses, l.License.Name)
			}
		}
	}
	if c.Hashes != nil {
		for _, h := range *c.Hashes {
			p.Hashes = append(p.Hashes, Hash{Algorithm: string(h.Algorithm), Value: h.Value})
		}
	}
	if c.Evidence != nil && c.Evidence.Occurrences != nil {
		for _, o := range *c.Evidence.Occurrences {
			if o.Location != "" {
				p.Locations = append(p.Locations, o.Location)
			}
		}
	}
	if c.Properties != nil {
		for _, pr := range *c.Properties {
			if pr.Name == ecosystemProperty {
				p.Ecosystem = pr.Value
				continue
			}
			if p.Properties == nil {
				p.Properties = map[string]string{}
			}
			p.Properties[pr.Name] = pr.Value
		}
	}
	return p
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
