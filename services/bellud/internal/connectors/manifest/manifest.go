// Package manifest defines the Connector_Manifest contract shared by built-in
// and plugin connectors, its validation rules and the read-only classifier.
package manifest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Bounds from Requirement 8.2.
const (
	MaxIDLen        = 64
	MaxNameLen      = 64
	MinAuthMethods  = 1
	MaxAuthMethods  = 5
	MaxPermissions  = 50
	MaxOperations   = 200
	MaxEgress       = 50
	MinEntities     = 1
	MaxEntities     = 100
	maxFieldLen     = 256
	maxOperationMax = 64 << 20
)

// Operation classes.
const (
	ClassRead = "read"
	ClassAuth = "auth"
)

//go:embed manifest.schema.json
var schema []byte

// Schema returns a copy of the embedded JSON Schema for Connector_Manifest.
func Schema() []byte { return bytes.Clone(schema) }

// Manifest declares a connector: auth methods, permissions, read allowlist,
// egress allowlist and produced graph kinds.
type Manifest struct {
	ID          string       `json:"id"`
	Version     string       `json:"version"`
	Name        string       `json:"name"`
	Icon        string       `json:"icon"`
	AuthMethods []AuthMethod `json:"auth_methods"`
	Permissions []Permission `json:"permissions"`
	Operations  []Operation  `json:"operations"`
	Egress      []string     `json:"egress"`
	Entities    []string     `json:"entities"`
	Builtin     bool         `json:"-"`
}

// AuthMethod is one way to authenticate. Disabled methods are listed for the
// catalog UI but cannot be selected.
type AuthMethod struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	DisabledReason string `json:"disabled_reason,omitempty"`
}

// Permission is a requested provider permission. Every permission must be
// read-only.
type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ReadOnly    bool   `json:"read_only"`
}

// Operation is one allowlisted provider call.
type Operation struct {
	// Name is e.g. "ec2:DescribeInstances" or "GET /repos/{o}/{r}/pulls".
	Name string `json:"name"`
	// Class is "read" or "auth" (auth: lifecycle only, never collectors/agent).
	Class string `json:"class"`
	// Method is the HTTP method; empty for AWS-style operations.
	Method string `json:"method,omitempty"`
	Host   string `json:"host"`
	// Path is a pattern; empty for AWS where the operation name decides.
	Path string `json:"path,omitempty"`
	// Query marks a POST that is a read query (e.g. a GraphQL query).
	Query     bool     `json:"query,omitempty"`
	StripKeys []string `json:"strip_keys,omitempty"`
	MaxBytes  int      `json:"max_bytes,omitempty"`
}

// FieldError names an invalid field. It never contains the offending value.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Field + ": " + e.Message }

var (
	idRe     = regexp.MustCompile(`^[a-z0-9-]+$`)
	hostRe   = regexp.MustCompile(`^(\*\.)?[a-z0-9{}]([a-z0-9{}.-]*[a-z0-9{}])?$`)
	kindRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-((0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)
)

var httpMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// Validate returns one FieldError per invalid field. Values are never echoed.
func Validate(m Manifest) []FieldError {
	var errs []FieldError
	add := func(field, msg string) { errs = append(errs, FieldError{Field: field, Message: msg}) }

	if n := utf8.RuneCountInString(m.ID); n < 1 || n > MaxIDLen || !idRe.MatchString(m.ID) {
		add("id", "must be 1-64 characters of a-z, 0-9 or -")
	}
	if !semverRe.MatchString(m.Version) {
		add("version", "must be a semantic version")
	}
	if n := utf8.RuneCountInString(m.Name); n < 1 || n > MaxNameLen || strings.TrimSpace(m.Name) == "" {
		add("name", "must be 1-64 characters")
	}
	if utf8.RuneCountInString(m.Icon) > maxFieldLen {
		add("icon", "too long")
	}

	if n := len(m.AuthMethods); n < MinAuthMethods || n > MaxAuthMethods {
		add("auth_methods", "must have 1-5 entries")
	}
	for i, a := range m.AuthMethods {
		p := fmt.Sprintf("auth_methods[%d]", i)
		if blank(a.ID, 64) {
			add(p+".id", "must be 1-64 characters")
		}
		if blank(a.Name, 64) {
			add(p+".name", "must be 1-64 characters")
		}
		if !a.Enabled && a.DisabledReason == "" {
			add(p+".disabled_reason", "required when the method is disabled")
		}
		if utf8.RuneCountInString(a.DisabledReason) > maxFieldLen {
			add(p+".disabled_reason", "too long")
		}
	}

	if len(m.Permissions) > MaxPermissions {
		add("permissions", "must have 0-50 entries")
	}
	for i, pm := range m.Permissions {
		p := fmt.Sprintf("permissions[%d]", i)
		if blank(pm.Name, maxFieldLen) {
			add(p+".name", "must be 1-256 characters")
		}
		if utf8.RuneCountInString(pm.Description) > 1024 {
			add(p+".description", "too long")
		}
		if !pm.ReadOnly {
			add(p+".read_only", "must be true")
		}
	}

	if len(m.Operations) > MaxOperations {
		add("operations", "must have 0-200 entries")
	}
	for i, op := range m.Operations {
		validateOperation(fmt.Sprintf("operations[%d]", i), op, add)
	}

	if len(m.Egress) > MaxEgress {
		add("egress", "must have 0-50 entries")
	}
	for i, h := range m.Egress {
		if !validHost(h) {
			add(fmt.Sprintf("egress[%d]", i), "must be a lowercase host pattern")
		}
	}

	if n := len(m.Entities); n < MinEntities || n > MaxEntities {
		add("entities", "must have 1-100 entries")
	}
	for i, k := range m.Entities {
		if !kindRe.MatchString(k) {
			add(fmt.Sprintf("entities[%d]", i), "must be a graph kind name")
		}
	}
	return errs
}

func validateOperation(p string, op Operation, add func(field, msg string)) {
	if blank(op.Name, maxFieldLen) {
		add(p+".name", "must be 1-256 characters")
	}
	switch op.Class {
	case ClassRead:
		if IsWrite(op) {
			add(p+".class", "operation is a write and cannot be class read")
		}
	case ClassAuth:
	default:
		add(p+".class", "must be read or auth")
	}
	if op.Method != "" && !httpMethods[op.Method] {
		add(p+".method", "must be an uppercase HTTP method")
	}
	if !validHost(op.Host) {
		add(p+".host", "must be a lowercase host pattern")
	}
	if utf8.RuneCountInString(op.Path) > 512 || (op.Path != "" && !strings.HasPrefix(op.Path, "/")) {
		add(p+".path", "must be empty or start with /")
	}
	if op.Query && op.Method != "POST" {
		add(p+".query", "only valid for POST")
	}
	if len(op.StripKeys) > 50 {
		add(p+".strip_keys", "must have 0-50 entries")
	}
	for i, k := range op.StripKeys {
		if blank(k, 128) {
			add(fmt.Sprintf("%s.strip_keys[%d]", p, i), "must be 1-128 characters")
		}
	}
	if op.MaxBytes < 0 || op.MaxBytes > maxOperationMax {
		add(p+".max_bytes", "out of range")
	}
}

func blank(s string, max int) bool {
	n := utf8.RuneCountInString(s)
	return n < 1 || n > max || strings.TrimSpace(s) == ""
}

func validHost(h string) bool {
	return len(h) >= 1 && len(h) <= 253 && hostRe.MatchString(h)
}

// awsReadVerbs are the AWS action verb prefixes classified as reads. Anything
// else is a write (fail closed).
var awsReadVerbs = []string{"Describe", "List", "Get", "Head", "Simulate", "Lookup", "Search"}

// IsWrite reports whether op mutates provider state. With a Method set:
// GET/HEAD/OPTIONS are reads, POST/PUT/PATCH/DELETE are writes unless the
// operation is marked as a read Query (POST only), and unknown methods are
// writes. Without a Method the name is an AWS action ("svc:Verb..."); only
// known read verb prefixes are reads, everything else is a write.
func IsWrite(op Operation) bool {
	switch op.Method {
	case "GET", "HEAD", "OPTIONS":
		return false
	case "POST":
		return !op.Query
	case "":
		return !awsRead(op.Name)
	default:
		return true
	}
}

func awsRead(name string) bool {
	_, action, ok := strings.Cut(name, ":")
	if !ok || action == "" {
		return false
	}
	for _, v := range awsReadVerbs {
		rest, found := strings.CutPrefix(action, v)
		if !found {
			continue
		}
		// The verb must end at a word boundary: end of string or uppercase.
		if rest == "" || (rest[0] >= 'A' && rest[0] <= 'Z') {
			return true
		}
	}
	return false
}

// Marshal encodes m as JSON with empty (never null) arrays.
func Marshal(m Manifest) ([]byte, error) {
	if m.AuthMethods == nil {
		m.AuthMethods = []AuthMethod{}
	}
	if m.Permissions == nil {
		m.Permissions = []Permission{}
	}
	if m.Operations == nil {
		m.Operations = []Operation{}
	}
	if m.Egress == nil {
		m.Egress = []string{}
	}
	if m.Entities == nil {
		m.Entities = []string{}
	}
	return json.Marshal(m)
}

// Parse decodes a manifest, rejecting unknown fields. It does not validate;
// call Validate on the result.
func Parse(data []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: invalid JSON document")
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("manifest: trailing data")
	}
	return m, nil
}
