//go:build osvmatch

package vulnmatch

import "github.com/google/osv-scalibr/semantic"

// OSVEnabled reports whether the OSV-Scanner version comparators are built in.
const OSVEnabled = true

// osvEcosystems maps purl types to the OSV ecosystem whose native ordering
// Grype's comparators approximate: PEP 440 (PyPI), Maven, NuGet, RubyGems and
// Packagist.
var osvEcosystems = map[string]string{
	"pypi":     "PyPI",
	"maven":    "Maven",
	"nuget":    "NuGet",
	"gem":      "RubyGems",
	"composer": "Packagist",
}

// osvCompare orders a and b with OSV-Scanner's version library
// (osv-scalibr/semantic). It is a pure in-process comparison: no OSV API call
// and no network. ok is false for other ecosystems and for versions the
// library rejects.
func osvCompare(purlType, a, b string) (int, bool) {
	eco, ok := osvEcosystems[purlType]
	if !ok {
		return 0, false
	}
	va, err := semantic.Parse(a, eco)
	if err != nil {
		return 0, false
	}
	c, err := va.CompareStr(b)
	if err != nil {
		return 0, false
	}
	return c, true
}
