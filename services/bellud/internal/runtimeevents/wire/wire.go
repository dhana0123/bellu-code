// Package wire is the sensor-to-bellud frame format for runtime events. A
// connection carries newline-delimited JSON frames. The first frame must be a
// hello carrying the per-workspace HMAC; later frames are events or status
// reports. It depends only on the standard library so the sensor can import it.
package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
)

// Frame kinds.
const (
	KindHello  = "hello"
	KindEvent  = "event"
	KindStatus = "status"
)

// Event types (Requirement 15.3), also the drop-counter keys.
const (
	TypeProcessExec     = "process_exec"
	TypeNetworkConnect  = "network_connect"
	TypeFileWrite       = "file_write_sensitive"
	TypeShellSpawn      = "shell_spawn"
	TypePrivilegeChange = "privilege_change"
	TypeContainerEscape = "container_escape"
)

// Sensor statuses.
const (
	StatusOK          = "ok"
	StatusUnsupported = "unsupported"
)

// MaxFrameBytes bounds one frame on the wire; larger frames are rejected.
const MaxFrameBytes = 64 << 10

// MaxArgsChars is the argument limit after redaction (Requirement 15.4).
const MaxArgsChars = 4096

// Frame is one line on the wire. Exactly the field named by Kind is set.
type Frame struct {
	Kind   string  `json:"kind"`
	Hello  *Hello  `json:"hello,omitempty"`
	Event  *Event  `json:"event,omitempty"`
	Status *Status `json:"status,omitempty"`
}

// Hello authenticates a Unix-socket connection. MAC is hex HMAC-SHA256 over
// Workspace, Node and TS (unix seconds) keyed with the workspace token.
type Hello struct {
	Workspace string `json:"workspace"`
	Node      string `json:"node"`
	TS        int64  `json:"ts"`
	MAC       string `json:"mac"`
}

// Event is one runtime event. Fields the sensor could not obtain are empty and
// named in Unavailable (for example "container_id", "pod", "namespace").
type Event struct {
	TS          time.Time `json:"ts"`
	Type        string    `json:"type"`
	Node        string    `json:"node"`
	Namespace   string    `json:"namespace,omitempty"`
	Pod         string    `json:"pod,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
	ProcessPath string    `json:"process_path,omitempty"`
	Args        string    `json:"args,omitempty"` // already redacted by the sensor
	User        string    `json:"user,omitempty"`
	Unavailable []string  `json:"unavailable,omitempty"`
}

// Status reports sensor health. Reason is kernel_too_old or btf_missing when
// Status is unsupported. Drops maps event type to dropped count.
type Status struct {
	Status string           `json:"status"`
	Reason string           `json:"reason,omitempty"`
	Drops  map[string]int64 `json:"drops,omitempty"`
}

// Sign returns the hex HMAC for a hello.
func Sign(key []byte, workspace, node string, ts int64) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(workspace + "\x00" + node + "\x00" + strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(m.Sum(nil))
}

// NewHello builds a signed hello frame.
func NewHello(key []byte, workspace, node string, now time.Time) Frame {
	ts := now.Unix()
	return Frame{Kind: KindHello, Hello: &Hello{Workspace: workspace, Node: node, TS: ts, MAC: Sign(key, workspace, node, ts)}}
}

// Marshal encodes a frame as one line including the trailing newline.
func Marshal(f Frame) ([]byte, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
