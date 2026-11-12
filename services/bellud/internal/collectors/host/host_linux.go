//go:build linux

package host

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

type proc struct {
	pid       string
	startTime string
	comm      string
	ppid      string
	uid       string
	exe       string
	argv0     string
}

type sock struct {
	protocol string
	addr     string
	port     string
	inode    string
}

// Collect reads the current processes and listening sockets.
func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	hostname := c.hostname
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return graph.Batch{}, fmt.Errorf("hostname: %w", err)
		}
		hostname = h
	}
	root := string(c.procRoot)
	b := graph.Batch{Collector: Name, ObservedAt: time.Now().UTC()}
	hostID, err := identity.Hash("host", map[string]string{"hostname": hostname})
	if err != nil {
		return graph.Batch{}, err
	}
	b.Entities = append(b.Entities, batch.Entity{Type: "host", Identity: map[string]string{"hostname": hostname}})

	procs, owners, err := readProcs(ctx, root)
	if err != nil {
		return graph.Batch{}, err
	}
	procID := map[string]string{} // pid -> entity id
	for _, p := range procs {
		ident := map[string]string{"host": hostname, "pid": p.pid, "start_time": p.startTime}
		id, err := identity.Hash("process", ident)
		if err != nil {
			return graph.Batch{}, err
		}
		procID[p.pid] = string(id)
		attrs := map[string]any{"comm": p.comm, "ppid": p.ppid, "uid": p.uid}
		if p.exe != "" {
			attrs["exe"] = p.exe
		}
		if p.argv0 != "" {
			attrs["argv0"] = p.argv0
		}
		b.Entities = append(b.Entities, batch.Entity{Type: "process", Identity: ident, Attributes: attrs})
		b.Relations = append(b.Relations, batch.Relation{Type: "runs_on", From: string(id), To: string(hostID)})
	}

	seen := map[string]bool{}
	for _, f := range []struct{ file, proto string }{
		{"net/tcp", "tcp"}, {"net/tcp6", "tcp"}, {"net/udp", "udp"}, {"net/udp6", "udp"},
	} {
		socks, err := readSocks(filepath.Join(root, f.file), f.proto)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return graph.Batch{}, err
		}
		for _, s := range socks {
			ident := map[string]string{"host": hostname, "protocol": s.protocol, "address": s.addr, "port": s.port}
			id, err := identity.Hash("listening_port", ident)
			if err != nil {
				return graph.Batch{}, err
			}
			if seen[string(id)] {
				continue
			}
			seen[string(id)] = true
			b.Entities = append(b.Entities, batch.Entity{Type: "listening_port", Identity: ident})
			b.Relations = append(b.Relations, batch.Relation{Type: "on", From: string(id), To: string(hostID)})
			if pid, ok := owners[s.inode]; ok {
				if pe, ok := procID[pid]; ok {
					b.Relations = append(b.Relations, batch.Relation{Type: "owned_by", From: string(id), To: pe})
				}
			}
		}
	}
	return b, ctx.Err()
}

// readProcs lists processes and maps socket inodes to owning pids (best effort).
func readProcs(ctx context.Context, root string) ([]proc, map[string]string, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, err
	}
	var procs []proc
	owners := map[string]string{}
	for _, e := range ents {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !e.IsDir() || !isNumeric(e.Name()) {
			continue
		}
		dir := filepath.Join(root, e.Name())
		p, ok := readProc(dir, e.Name())
		if !ok {
			continue // exited or unreadable
		}
		procs = append(procs, p)
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") || !strings.HasSuffix(l, "]") {
				continue
			}
			ino := l[len("socket:[") : len(l)-1]
			if _, dup := owners[ino]; !dup {
				owners[ino] = p.pid
			}
		}
	}
	return procs, owners, nil
}

func readProc(dir, pid string) (proc, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return proc{}, false
	}
	comm, ppid, start, ok := parseStat(string(raw))
	if !ok {
		return proc{}, false
	}
	p := proc{pid: pid, comm: comm, ppid: ppid, startTime: start}
	if st, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		p.uid = parseUID(string(st))
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.exe = filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	}
	if cl, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		// Only argv[0]: later arguments may carry secrets.
		p.argv0, _, _ = strings.Cut(string(cl), "\x00")
	}
	return p, true
}

// parseStat extracts comm, ppid (field 4) and starttime (field 22).
func parseStat(s string) (comm, ppid, start string, ok bool) {
	l, r := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if l < 0 || r < l {
		return
	}
	f := strings.Fields(s[r+1:]) // f[0] is field 3
	if len(f) < 20 {
		return
	}
	return s[l+1 : r], f[1], f[19], true
}

func parseUID(status string) string {
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

// readSocks returns LISTEN tcp sockets or bound udp sockets from a proc net table.
func readSocks(path, proto string) ([]sock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []sock
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		if proto == "tcp" && f[3] != "0A" {
			continue
		}
		addr, port, ok := parseAddr(f[1])
		if !ok || (proto == "udp" && port == 0) {
			continue
		}
		out = append(out, sock{protocol: proto, addr: addr, port: strconv.Itoa(port), inode: f[9]})
	}
	return out, sc.Err()
}

// parseAddr decodes "0100007F:0050" or the 32-hex-digit IPv6 form. Each
// 32-bit word is stored in host (little-endian) byte order.
func parseAddr(s string) (string, int, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok || (len(h) != 8 && len(h) != 32) {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, false
	}
	var raw [16]byte
	n := len(h) / 2
	for i := 0; i < n; i++ {
		v, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return "", 0, false
		}
		raw[i] = byte(v)
	}
	for w := 0; w < n; w += 4 { // reverse each word
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	if n == 4 {
		return netip.AddrFrom4([4]byte(raw[:4])).String(), int(port), true
	}
	return netip.AddrFrom16(raw).String(), int(port), true
}

func isNumeric(s string) bool {
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}
