//go:build !osvmatch

package vulnmatch

// OSVEnabled reports whether the OSV-Scanner version comparators are built in.
const OSVEnabled = false

// osvCompare is the stub used without the osvmatch build tag: it never
// decides, so Grype's comparators answer.
func osvCompare(string, string, string) (int, bool) { return 0, false }
