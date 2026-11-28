//go:build linux

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/sensor_bpfel.o
var sensorObject []byte

// ErrObjectMissing means the embedded BPF object has not been built yet (see generate.go).
var ErrObjectMissing = errors.New("bpf object not built: regenerate bpf/sensor_bpfel.o")

// Raw event kinds; keep in sync with bpf/sensor.h.
const (
	kindExec           = 1
	kindFileWrite      = 2
	kindConnect        = 3
	kindPrivChange     = 4
	kindContainerEsc   = 5
	kindShellContainer = 6
)

// rawEvent mirrors struct bellu_event in bpf/sensor.h.
type rawEvent struct {
	TsNs        uint64
	CgroupID    uint64
	Kind        uint32
	PID         uint32
	UID         uint32
	InContainer uint32
	Addr4       [4]byte
	Port        uint16
	Family      uint16
	Comm        [16]byte
	Path        [256]byte
	Args        [256]byte
}

// tracepoints maps each program to its syscall tracepoint.
var tracepoints = map[string]string{
	"bellu_exec":      "sys_enter_execve",
	"bellu_openat":    "sys_enter_openat",
	"bellu_connect":   "sys_enter_connect",
	"bellu_setuid":    "sys_enter_setuid",
	"bellu_setresuid": "sys_enter_setresuid",
	"bellu_setns":     "sys_enter_setns",
	"bellu_unshare":   "sys_enter_unshare",
}

// BPFSource is the cilium/ebpf EventSource. It only observes; programs never block or alter syscalls.
type BPFSource struct {
	// CgroupIDs limits events to these cgroups in the kernel. Empty means all cgroups.
	CgroupIDs []uint64
	// Node is stamped on each event.
	Node string
	// Object overrides the embedded object (tests).
	Object []byte
}

var _ EventSource = (*BPFSource)(nil)

// Start loads and attaches the programs, then emits events until ctx is cancelled.
func (s *BPFSource) Start(ctx context.Context, emit func(Event)) error {
	obj := s.Object
	if obj == nil {
		obj = sensorObject
	}
	if len(obj) == 0 {
		return ErrObjectMissing
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load bpf collection: %w", err)
	}
	defer coll.Close()

	if len(s.CgroupIDs) > 0 {
		var one uint32 = 1
		if err := coll.Maps["cgroup_filter_enabled"].Put(uint32(0), one); err != nil {
			return fmt.Errorf("enable cgroup filter: %w", err)
		}
		for _, id := range s.CgroupIDs {
			if err := coll.Maps["cgroup_filter"].Put(id, uint8(1)); err != nil {
				return fmt.Errorf("add cgroup %d: %w", id, err)
			}
		}
	}

	for prog, tp := range tracepoints {
		p := coll.Programs[prog]
		if p == nil {
			return fmt.Errorf("bpf program %s missing", prog)
		}
		l, err := link.Tracepoint("syscalls", tp, p, nil)
		if err != nil {
			return fmt.Errorf("attach %s: %w", tp, err)
		}
		defer l.Close()
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}
		var raw rawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		if e, ok := s.toEvent(raw); ok {
			emit(Normalize(e))
		}
	}
}

var eventIDSeq atomic.Uint64

func (s *BPFSource) toEvent(r rawEvent) (Event, bool) {
	e := Event{
		ID:          fmt.Sprintf("%d-%d-%d", os.Getpid(), r.TsNs, nextSeq()),
		TS:          time.Now().UTC(),
		Node:        s.Node,
		ContainerID: "",
		ProcessPath: cstr(r.Path[:]),
		Args:        cstr(r.Args[:]),
		User:        strconv.FormatUint(uint64(r.UID), 10),
	}
	switch r.Kind {
	case kindExec:
		e.Type = TypeProcessExec
	case kindFileWrite:
		e.Type = TypeFileWriteSensitive
	case kindConnect:
		e.Type = TypeNetConnect
		e.ProcessPath = cstr(r.Comm[:])
		e.Args = net.JoinHostPort(net.IP(r.Addr4[:]).String(), strconv.Itoa(int(r.Port)))
	case kindPrivChange:
		e.Type = TypePrivChange
		e.ProcessPath = cstr(r.Comm[:])
	case kindContainerEsc:
		e.Type = TypeContainerEscape
		e.ProcessPath = cstr(r.Comm[:])
	case kindShellContainer:
		e.Type = TypeShellInContainer
	default:
		return Event{}, false
	}
	return e, true
}

func nextSeq() uint64 {
	return eventIDSeq.Add(1)
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
