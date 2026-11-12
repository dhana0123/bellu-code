//go:build linux

package host

import (
	"context"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

func TestCollectFixture(t *testing.T) {
	c := New(time.Second, WithProcRoot("testdata/proc"), WithHostname("h1"))
	if c.Interval() != MinInterval || c.Name() != "host" {
		t.Fatalf("interval %v name %s", c.Interval(), c.Name())
	}
	b, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, e := range b.Entities {
		count[e.Type]++
		if e.Type == "process" && e.Identity["pid"] == "100" {
			if e.Identity["start_time"] != "98765" || e.Attributes["comm"] != "my (daemon)" ||
				e.Attributes["ppid"] != "1" || e.Attributes["uid"] != "1000" || e.Attributes["argv0"] != "/usr/bin/daemon" {
				t.Fatalf("bad process %+v", e)
			}
		}
		for _, v := range e.Attributes {
			if s, _ := v.(string); s == "--token=secret" {
				t.Fatal("leaked arg")
			}
		}
	}
	// tcp 22 (v4), tcp 53 (v4, no owner), tcp6 [::1]:80, udp 68 => 4 ports
	if count["host"] != 1 || count["process"] != 2 || count["listening_port"] != 4 {
		t.Fatalf("counts %v", count)
	}
	hostID, _ := identity.Hash("host", map[string]string{"hostname": "h1"})
	p100, _ := identity.Hash("process", map[string]string{"host": "h1", "pid": "100", "start_time": "98765"})
	p22, _ := identity.Hash("listening_port", map[string]string{"host": "h1", "protocol": "tcp", "address": "0.0.0.0", "port": "22"})
	p80, _ := identity.Hash("listening_port", map[string]string{"host": "h1", "protocol": "tcp", "address": "::1", "port": "80"})
	rel := map[[3]string]bool{}
	owned := 0
	for _, r := range b.Relations {
		if len(r.Attributes) != 0 {
			t.Fatal("relation attrs")
		}
		rel[[3]string{r.Type, r.From, r.To}] = true
		if r.Type == "owned_by" {
			owned++
		}
	}
	for _, w := range [][3]string{
		{"runs_on", string(p100), string(hostID)},
		{"on", string(p22), string(hostID)},
		{"owned_by", string(p22), string(p100)},
		{"owned_by", string(p80), string(p100)},
	} {
		if !rel[w] {
			t.Fatalf("missing relation %v", w)
		}
	}
	if owned != 2 {
		t.Fatalf("owned_by = %d", owned)
	}
}

func TestParseAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:0050":                         "127.0.0.1",
		"00000000:0016":                         "0.0.0.0",
		"B80D0120000000000000000001000000:01BB": "2001:db8::1",
	} {
		a, _, ok := parseAddr(in)
		if !ok || a != want {
			t.Fatalf("%s => %s %v, want %s", in, a, ok, want)
		}
	}
	if _, p, _ := parseAddr("0100007F:1F90"); p != 8080 {
		t.Fatal("port")
	}
}
