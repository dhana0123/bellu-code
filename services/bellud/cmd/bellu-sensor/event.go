//go:build linux

package main

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

// maxArgsLen is the maximum length of Event.Args in characters (Requirement 15.4).
const maxArgsLen = 4096

// failedArgs replaces args when redaction fails (Requirement 15.5).
const failedArgs = "[REDACTION_FAILED]"

// Runtime event types (Requirement 15.3).
const (
	TypeProcessExec        = "process_exec"
	TypeFileWriteSensitive = "file_write_sensitive"
	TypeNetConnect         = "net_connect"
	TypePrivChange         = "priv_change"
	TypeContainerEscape    = "container_escape"
	TypeShellInContainer   = "shell_in_container"
)

// Event is a placeholder for the wire type. Task 56.5 connects it to runtimeevents.Event.
type Event struct {
	ID          string    `json:"id"`
	TS          time.Time `json:"ts"`
	Type        string    `json:"type"`
	ContainerID string    `json:"container_id,omitempty"`
	Pod         string    `json:"pod,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Node        string    `json:"node,omitempty"`
	ProcessPath string    `json:"process_path,omitempty"`
	Args        string    `json:"args,omitempty"`
	User        string    `json:"user,omitempty"`
	// Unavailable names fields that could not be determined; the event is still sent.
	Unavailable []string `json:"unavailable"`
}

// EventSource produces runtime events until ctx is cancelled.
// The default implementation (task 56.2) uses cilium/ebpf.
type EventSource interface {
	Start(ctx context.Context, emit func(Event)) error
}

// Normalize redacts and truncates Args, and records fields that are unknown in Unavailable.
func Normalize(e Event) Event {
	if e.Args != "" {
		out, err := redact.Text(e.Args)
		if err != nil {
			out = failedArgs
		}
		e.Args = truncate(out, maxArgsLen)
	}
	e.Unavailable = unavailableFields(e)
	return e
}

func unavailableFields(e Event) []string {
	missing := []string{}
	for _, f := range []struct {
		name  string
		empty bool
	}{
		{"container_id", e.ContainerID == ""},
		{"pod", e.Pod == ""},
		{"namespace", e.Namespace == ""},
		{"node", e.Node == ""},
		{"process_path", e.ProcessPath == ""},
		{"args", e.Args == ""},
		{"user", e.User == ""},
	} {
		if f.empty {
			missing = append(missing, f.name)
		}
	}
	return missing
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
