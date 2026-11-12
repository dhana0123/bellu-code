// Package query holds the pure read-side algorithms of the Bellu Graph Engine.
package query

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
)

const cursorVersion = 1

// cursorBody is the JSON payload of a cursor. A is the keyset key, which
// encoding/json writes as standard base64.
type cursorBody struct {
	V int    `json:"v"`
	K string `json:"k"`
	Q uint64 `json:"q"`
	A []byte `json:"a"`
}

// EncodeCursor returns an opaque cursor binding key to a query kind and the
// hash of the normalized query.
func EncodeCursor(kind string, qhash uint64, key []byte) string {
	if key == nil {
		key = []byte{}
	}
	raw, err := json.Marshal(cursorBody{V: cursorVersion, K: kind, Q: qhash, A: key})
	if err != nil {
		// Marshalling a struct of string, integer and byte slice cannot fail.
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeCursor returns the keyset key held by s. A malformed cursor, or one
// issued for another kind or query, returns an error wrapping errs.Validation.
func DecodeCursor(kind string, qhash uint64, s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, malformedCursor()
	}
	var body cursorBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() {
		return nil, malformedCursor()
	}
	if body.V != cursorVersion || body.K != kind || body.Q != qhash || body.A == nil {
		return nil, malformedCursor()
	}
	return body.A, nil
}

func malformedCursor() error {
	return fmt.Errorf("%w: malformed cursor", errs.Validation)
}
