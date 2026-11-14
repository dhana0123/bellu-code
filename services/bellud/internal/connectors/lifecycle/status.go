// Package lifecycle holds the connection state machine and typed error set.
package lifecycle

import (
	"errors"
	"fmt"
)

// Status is a Connection_Status. "Removed" is a tombstone flag, not a status.
type Status string

const (
	StatusInitiated Status = "INITIATED"
	StatusVerifying Status = "VERIFYING"
	StatusActive    Status = "ACTIVE"
	StatusExpired   Status = "EXPIRED"
	StatusPaused    Status = "PAUSED"
	StatusError     Status = "ERROR"
)

// Statuses lists every status.
var Statuses = []Status{StatusInitiated, StatusVerifying, StatusActive, StatusExpired, StatusPaused, StatusError}

// ErrTransition is returned by Next for a change not on the Req 14.9 list.
var ErrTransition = errors.New("transition_rejected")

// transitions is the exact Req 14.9 table.
var transitions = map[Status][]Status{
	StatusInitiated: {StatusVerifying},
	StatusVerifying: {StatusActive, StatusError},
	StatusActive:    {StatusExpired, StatusPaused, StatusError},
	StatusPaused:    {StatusActive, StatusExpired, StatusError},
	StatusExpired:   {StatusVerifying},
	StatusError:     {StatusVerifying},
}

// Next reports whether from→to is allowed. It is pure and returns nil or an
// error wrapping ErrTransition.
func Next(from, to Status) error {
	for _, t := range transitions[from] {
		if t == to {
			return nil
		}
	}
	return fmt.Errorf("%w: %s -> %s", ErrTransition, from, to)
}
