// Package data embeds the data files of the bom package.
package data

import _ "embed"

// AISignatures is the built-in AI signature table (Requirement 6).
//
//go:embed ai-signatures.yaml
var AISignatures []byte

// EOL is the built-in end-of-life table and unsafe AI model format list.
//
//go:embed eol.json
var EOL []byte
