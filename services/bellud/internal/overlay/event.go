// Package overlay carries agent overlay events to the graph view. Events are
// transient: they are never stored and never become graph facts, so this
// package must not import the graph facade.
package overlay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Actions an Event may carry.
const (
	ActionFocusNode      = "focus_node"
	ActionWalkPath       = "walk_path"
	ActionProposedChange = "proposed_change"
)

// Event is one overlay instruction. For walk_path, Entity is the last element of Path.
type Event struct {
	Seq         uint64   `json:"seq"`
	Entity      string   `json:"entity"`
	Action      string   `json:"action"`
	Path        []string `json:"path,omitempty"`
	Explanation string   `json:"explanation"`
}

// ValidAction reports whether a is a known action.
func ValidAction(a string) bool {
	switch a {
	case ActionFocusNode, ActionWalkPath, ActionProposedChange:
		return true
	}
	return false
}

// Validate checks the event fields.
func (e Event) Validate() error {
	if !ValidAction(e.Action) {
		return fmt.Errorf("overlay: unknown action %q", e.Action)
	}
	if e.Entity == "" {
		return errors.New("overlay: entity is required")
	}
	return nil
}

// Encode returns the JSON form of e.
func Encode(e Event) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// Decode parses one event strictly: unknown fields, unknown actions, trailing
// data, and a missing entity are rejected.
func Decode(data []byte) (Event, error) {
	var e Event
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Event{}, fmt.Errorf("overlay: decode: %w", err)
	}
	if dec.More() {
		return Event{}, errors.New("overlay: trailing data after event")
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}
