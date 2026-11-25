package bom

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// DefaultSPDXVersion is used when Options.Version is empty and the format is SPDX.
const DefaultSPDXVersion = "2.3"

// bellu fields that SPDX has no slot for travel in the package and document
// "comment" fields as `bellu:<json>`, so ReadSPDX can restore them.
const commentPrefix = "bellu:"

const (
	spdxNoAssertion = "NOASSERTION"
	spdxNone        = "NONE"
	spdxDocumentID  = "SPDXRef-DOCUMENT"
	spdxNamespace   = "https://spdx.bellu.invalid/sbom/"
	defaultDocName  = "bellud-sbom"
)

// spdxExtras holds the Package fields SPDX cannot express. Ecosystem is always
// written, even when empty, so that its presence marks the comment as ours:
// ReadSPDX derives the ecosystem from the purl type only for documents
// without it.
type spdxExtras struct {
	Ecosystem  string            `json:"ecosystem"`
	Type       string            `json:"type,omitempty"`
	Licenses   []string          `json:"licenses,omitempty"` // only when there is more than one
	Locations  []string          `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type spdxDocExtras struct {
	Subject string `json:"subject"`
}

// spdxAlgorithms maps this package's hash names to SPDX checksum algorithms.
// Names without a hyphen after "SHA" are identical in both.
var spdxAlgorithms = map[string]common.ChecksumAlgorithm{
	"MD5": common.MD5, "SHA-1": common.SHA1, "SHA-256": common.SHA256, "SHA-384": common.SHA384,
	"SHA-512": common.SHA512, "SHA3-256": common.SHA3_256, "SHA3-384": common.SHA3_384,
	"SHA3-512": common.SHA3_512, "BLAKE2b-256": common.BLAKE2b_256,
	"BLAKE2b-384": common.BLAKE2b_384, "BLAKE2b-512": common.BLAKE2b_512, "BLAKE3": common.BLAKE3,
}

var fromSPDXAlgorithms = map[common.ChecksumAlgorithm]string{
	common.SHA1: "SHA-1", common.SHA256: "SHA-256", common.SHA384: "SHA-384", common.SHA512: "SHA-512",
}

type spdxItem struct {
	prepared
	id string // full SPDXID
}

// writeSPDX writes an SPDX 2.3 JSON document. The envelope is written by hand
// and each package is encoded separately, so memory does not grow with the
// size of the output. Validation finishes before the first byte is written.
func writeSPDX(ctx context.Context, w io.Writer, s SBOM, opts Options) error {
	prep, err := prepareItems(s)
	if err != nil {
		return err
	}
	items := make([]spdxItem, len(prep))
	pkgs := make([]v2_3.Package, len(prep))
	seen := make(map[string]int, len(prep))
	for i, it := range prep {
		items[i] = spdxItem{prepared: it, id: spdxID(it, seen)}
		if pkgs[i], err = toSPDXPackage(items[i]); err != nil {
			return err
		}
	}
	// Encode before writing too, so an encoding failure also leaves w untouched.
	encoded := make([][]byte, len(pkgs))
	for i := range pkgs {
		if encoded[i], err = json.Marshal(&pkgs[i]); err != nil {
			return fmt.Errorf("bom: encode spdx package %q: %w", pkgs[i].PackageName, err)
		}
	}

	now, serial := opts.Now, opts.Serial
	if now == nil {
		now = time.Now
	}
	if serial == nil {
		serial = newSerial
	}
	name := s.Subject
	if name == "" {
		name = defaultDocName
	}
	nameJSON, _ := json.Marshal(name)
	nsJSON, _ := json.Marshal(spdxNamespace + url.PathEscape(serial()))
	createdJSON, _ := json.Marshal(now().UTC().Format("2006-01-02T15:04:05Z"))
	var commentField string
	if s.Subject != "" {
		b, _ := json.Marshal(spdxDocExtras{Subject: s.Subject})
		cj, _ := json.Marshal(commentPrefix + string(b))
		commentField = `"comment":` + string(cj) + ","
	}

	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, `{"SPDXID":%q,"spdxVersion":"SPDX-%s","dataLicense":"CC0-1.0","name":%s,"documentNamespace":%s,%s"creationInfo":{"created":%s,"creators":["Tool: bellud"]},"packages":[`,
		spdxDocumentID, opts.Version, nameJSON, nsJSON, commentField, createdJSON)
	for i, b := range encoded {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if i > 0 {
			bw.WriteByte(',')
		}
		bw.WriteByte('\n')
		bw.Write(b)
	}
	if len(encoded) > 0 {
		bw.WriteByte('\n')
	}
	bw.WriteString(`],"relationships":[`)
	if len(items) == 0 {
		// Section 11.1 allows NONE as the target when the document describes nothing.
		bw.WriteString("\n" + relationship(spdxNone))
	}
	for i, it := range items {
		if i > 0 {
			bw.WriteByte(',')
		}
		bw.WriteByte('\n')
		bw.WriteString(relationship(it.id))
	}
	bw.WriteString("\n]}\n")
	return bw.Flush()
}

func relationship(target string) string {
	return fmt.Sprintf(`{"spdxElementId":%q,"relationshipType":"DESCRIBES","relatedSpdxElement":%q}`, spdxDocumentID, target)
}

// spdxID derives a stable id from the purl, or from type, name and version.
// Equal ids get a suffix in sorted order, so they stay stable between runs.
func spdxID(it prepared, seen map[string]int) string {
	key := it.purl
	if key == "" {
		key = it.typ + "\x00" + it.pkg.Name + "\x00" + deref(it.pkg.Version)
	}
	if seen[key]++; seen[key] > 1 {
		key = fmt.Sprintf("%s#%d", key, seen[key])
	}
	sum := sha256.Sum256([]byte(key))
	return "SPDXRef-Package-" + hex.EncodeToString(sum[:8])
}

func toSPDXPackage(it spdxItem) (v2_3.Package, error) {
	p := it.pkg
	out := v2_3.Package{
		PackageName:             p.Name,
		PackageSPDXIdentifier:   common.ElementID(strings.TrimPrefix(it.id, "SPDXRef-")),
		PackageVersion:          deref(p.Version),
		PackageDownloadLocation: spdxNoAssertion,
		PackageLicenseDeclared:  spdxNoAssertion,
		PackageSupplier:         &common.Supplier{Supplier: spdxNoAssertion},
	}
	if sup := deref(p.Supplier); sup != "" {
		out.PackageSupplier = &common.Supplier{SupplierType: "Organization", Supplier: sup}
	}
	lic := sortedUnique(p.Licenses)
	extras := spdxExtras{Ecosystem: p.Ecosystem, Type: p.Type, Locations: sortedUnique(p.Locations), Properties: p.Properties}
	switch len(lic) {
	case 0:
	case 1:
		out.PackageLicenseDeclared = lic[0]
	default:
		extras.Licenses = lic
		parts := make([]string, len(lic))
		for i, l := range lic {
			parts[i] = l
			if strings.ContainsAny(l, " ()") {
				parts[i] = "(" + l + ")"
			}
		}
		out.PackageLicenseDeclared = strings.Join(parts, " AND ")
	}
	if it.purl != "" {
		out.PackageExternalReferences = []*v2_3.PackageExternalReference{
			{Category: common.CategoryPackageManager, RefType: common.TypePackageManagerPURL, Locator: it.purl},
		}
	}
	for _, h := range p.Hashes {
		alg, ok := spdxAlgorithms[h.Algorithm]
		if !ok {
			return out, fmt.Errorf("%w: %q has hash algorithm %q that SPDX 2.3 cannot express", ErrInvalidPackage, p.Name, h.Algorithm)
		}
		out.PackageChecksums = append(out.PackageChecksums, common.Checksum{Algorithm: alg, Value: h.Value})
	}
	sort.Slice(out.PackageChecksums, func(a, b int) bool {
		x, y := out.PackageChecksums[a], out.PackageChecksums[b]
		if x.Algorithm != y.Algorithm {
			return x.Algorithm < y.Algorithm
		}
		return x.Value < y.Value
	})
	// json.Marshal sorts map keys, so the comment is deterministic.
	b, err := json.Marshal(extras)
	if err != nil {
		return out, err
	}
	out.PackageComment = commentPrefix + string(b)
	return out, nil
}

// ReadSPDX parses an SPDX 2.3 JSON document. Any other spdxVersion fails with
// ErrUnsupportedVersion.
//
// A declared license of NOASSERTION or NONE reads back as no license, which
// is how the writer encodes an absent one. A supplier of "Person: X" and
// "Organization: X" both read back as X. The ecosystem, component type,
// locations, properties and the license list come from the comment the
// writer adds; for documents without it the ecosystem is the purl type.
func ReadSPDX(r io.Reader) (SBOM, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return SBOM{}, fmt.Errorf("bom: parse spdx: %w", err)
	}
	var head struct {
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return SBOM{}, fmt.Errorf("bom: parse spdx: %w", err)
	}
	if !strings.HasPrefix(head.SPDXVersion, "SPDX-") {
		return SBOM{}, fmt.Errorf("bom: parse spdx: spdxVersion is %q", head.SPDXVersion)
	}
	if v := strings.TrimPrefix(head.SPDXVersion, "SPDX-"); !versionSupported(FormatSPDXJSON, v) {
		return SBOM{}, unsupportedVersion(FormatSPDXJSON, v)
	}
	var doc v2_3.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return SBOM{}, fmt.Errorf("bom: parse spdx: %w", err)
	}
	var out SBOM
	if x, ok, err := readExtras[spdxDocExtras](doc.DocumentComment); err != nil {
		return SBOM{}, err
	} else if ok {
		out.Subject = x.Subject
	}
	if len(doc.Packages) > 0 {
		out.Packages = make([]Package, 0, len(doc.Packages))
	}
	for _, sp := range doc.Packages {
		p, err := fromSPDXPackage(sp)
		if err != nil {
			return SBOM{}, err
		}
		out.Packages = append(out.Packages, p)
	}
	return out, nil
}

func fromSPDXPackage(sp *v2_3.Package) (Package, error) {
	p := Package{Name: sp.PackageName, Version: strPtr(sp.PackageVersion)}
	for _, ref := range sp.PackageExternalReferences {
		if ref.Category == common.CategoryPackageManager && ref.RefType == common.TypePackageManagerPURL {
			p.Purl = strPtr(ref.Locator)
			break
		}
	}
	if sup := sp.PackageSupplier; sup != nil && sup.Supplier != spdxNoAssertion {
		p.Supplier = strPtr(sup.Supplier)
	}
	if l := sp.PackageLicenseDeclared; l != "" && l != spdxNoAssertion && l != spdxNone {
		p.Licenses = []string{l}
	}
	for _, c := range sp.PackageChecksums {
		alg, ok := fromSPDXAlgorithms[c.Algorithm]
		if !ok {
			alg = string(c.Algorithm)
		}
		p.Hashes = append(p.Hashes, Hash{Algorithm: alg, Value: c.Value})
	}
	x, ok, err := readExtras[spdxExtras](sp.PackageComment)
	if err != nil {
		return p, err
	}
	if !ok {
		if p.Purl != nil {
			if rest, found := strings.CutPrefix(*p.Purl, "pkg:"); found {
				p.Ecosystem, _, _ = strings.Cut(rest, "/")
			}
		}
		return p, nil
	}
	p.Ecosystem, p.Type, p.Locations, p.Properties = x.Ecosystem, x.Type, x.Locations, x.Properties
	if len(x.Licenses) > 0 {
		p.Licenses = x.Licenses
	}
	return p, nil
}

// readExtras decodes a `bellu:<json>` comment. ok is false when the comment
// is not one of ours.
func readExtras[T any](comment string) (x T, ok bool, err error) {
	body, found := strings.CutPrefix(comment, commentPrefix)
	if !found {
		return x, false, nil
	}
	if err := json.Unmarshal([]byte(body), &x); err != nil {
		return x, false, fmt.Errorf("bom: parse spdx: bad %s comment: %w", commentPrefix, err)
	}
	return x, true, nil
}
