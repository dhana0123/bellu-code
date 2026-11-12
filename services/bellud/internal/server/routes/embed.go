package routes

import (
	_ "embed"
	"strings"
)

//go:embed routes.yaml
var embedded []byte

// Embedded returns the raw bytes of the embedded routes.yaml.
func Embedded() []byte { return append([]byte(nil), embedded...) }

// MustLoadEmbedded parses and validates the embedded routes.yaml and panics on
// failure. Totality against the protocol operation list is checked in tests.
func MustLoadEmbedded() *Table {
	t, err := Load(strings.NewReader(string(embedded)))
	if err != nil {
		panic("routes: invalid embedded routes.yaml: " + err.Error())
	}
	return t
}
