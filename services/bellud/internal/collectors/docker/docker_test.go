package docker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const sockEnvSecret = "SUPERSECRETVALUE"

func fakeDocker(t *testing.T) (string, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		switch r.URL.Path {
		case "/containers/json":
			w.Write([]byte(`[{"Id":"c1"}]`))
		case "/containers/c1/json":
			w.Write([]byte(`{"Id":"c1","Name":"/web","Image":"sha256:img1","State":{"Status":"running"},
"Config":{"Image":"nginx:1","User":"root","Env":["Z=` + sockEnvSecret + `","A=b=c"],"Labels":{"k":"v"}},
"HostConfig":{"Privileged":true,"NetworkMode":"bridge"},
"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"n1"}},"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}},
"Mounts":[{"Type":"volume","Name":"v1"},{"Type":"bind","Name":""}]}`))
		case "/images/json":
			w.Write([]byte(`[{"Id":"sha256:img1","RepoTags":["nginx:1"],"Size":5}]`))
		case "/networks":
			w.Write([]byte(`[{"Id":"n1","Name":"bridge","Driver":"bridge","Scope":"local"}]`))
		case "/volumes":
			w.Write([]byte(`{"Volumes":[{"Name":"v1","Driver":"local"}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return sock, &calls
}

func TestCollect(t *testing.T) {
	sock, calls := fakeDocker(t)
	c := New(WithSocket(sock))
	b, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b.Collector != "docker" {
		t.Fatalf("collector %q", b.Collector)
	}
	kinds := map[string]int{}
	for _, e := range b.Entities {
		kinds[e.Type]++
		if e.Type == "container" {
			keys := e.Attributes["env_keys"].([]string)
			if len(keys) != 2 || keys[0] != "A" || keys[1] != "Z" {
				t.Fatalf("env_keys %v", keys)
			}
			if e.Attributes["privileged"] != true || e.Attributes["name"] != "web" {
				t.Fatalf("attrs %v", e.Attributes)
			}
		}
		if strings.Contains(strings.Join(flatten(e.Attributes), "|"), sockEnvSecret) {
			t.Fatal("env value leaked")
		}
	}
	for _, k := range []string{"container", "image", "network", "volume"} {
		if kinds[k] != 1 {
			t.Fatalf("kinds %v", kinds)
		}
	}
	rt := map[string]int{}
	for _, r := range b.Relations {
		rt[r.Type]++
		if len(r.Attributes) != 0 {
			t.Fatal("relation attrs")
		}
	}
	if rt["uses"] != 1 || rt["attached_to"] != 1 || rt["mounts"] != 1 {
		t.Fatalf("relations %v", rt)
	}
	for _, call := range *calls {
		if !strings.HasPrefix(call, "GET ") {
			t.Fatalf("non-GET call %s", call)
		}
	}
}

func flatten(m map[string]any) []string {
	var out []string
	for _, v := range m {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case []string:
			out = append(out, x...)
		}
	}
	return out
}

func TestAbsentSocket(t *testing.T) {
	c := New(WithSocket(filepath.Join(t.TempDir(), "none.sock")))
	b, err := c.Collect(context.Background())
	if err != nil || b.Collector != "docker" || len(b.Entities) != 0 {
		t.Fatalf("got %+v, %v", b, err)
	}
}

func TestReadOnlyAndInterval(t *testing.T) {
	sock, _ := fakeDocker(t)
	c := New(WithSocket(sock), WithInterval(time.Second))
	if c.Interval() < 30*time.Second {
		t.Fatal("interval below minimum")
	}
	req, _ := http.NewRequest(http.MethodPost, "http://docker/containers/c1/kill", nil)
	if _, err := c.client.Do(req); err == nil {
		t.Fatal("POST not refused")
	}
}

func TestSocketPath(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///tmp/x.sock")
	if SocketPath() != "/tmp/x.sock" {
		t.Fatal(SocketPath())
	}
	t.Setenv("DOCKER_HOST", "tcp://h:1")
	if SocketPath() != DefaultSocket {
		t.Fatal(SocketPath())
	}
}
