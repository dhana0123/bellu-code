// Package errs defines the error sentinels shared across the Bellu Graph
// Engine. Callers wrap them with %w and test with errors.Is.
package errs

import "errors"

var (
	// Validation reports malformed or unacceptable caller input.
	Validation = errors.New("validation failed")
	// NotFound reports that a requested entity, relation or event is absent.
	NotFound = errors.New("not found")
	// Unavailable reports that the Engine cannot serve the request right now.
	Unavailable = errors.New("unavailable")
	// Locked reports that the store is held by another process.
	Locked = errors.New("locked")
	// Corrupt reports damaged persisted data.
	Corrupt = errors.New("corrupt data")
	// InsecurePermissions reports storage with unsafe filesystem permissions.
	InsecurePermissions = errors.New("insecure permissions")
	// Forbidden reports an operation the caller is not allowed to perform.
	Forbidden = errors.New("forbidden")
	// Overflow reports that a size, count or numeric limit was exceeded.
	Overflow = errors.New("overflow")
)
