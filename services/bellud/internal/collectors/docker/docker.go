// Package docker is the Docker collector. It reads container, image, network
// and volume state through a read-only subset of the Docker Engine API (GET
// list/inspect only) over the daemon's unix socket, using only the stdlib.
//
// Container environment values are dropped as soon as an inspect response is
// decoded; only the sorted variable names are kept (env_keys).
//
// An absent socket is a normal state: Collect returns an empty batch and no
// error. An empty full observation retires previously seen docker entities,
// which is the intended outcome when Docker goes away. A socket that exists
// but cannot be opened (permission denied) is returned as a clear error; the
// runner records it in collector_status and rate-limits logging.
//
// runs_on (container -> host) is not emitted: the host entity belongs to the
// host collector and a relation to an entity absent from the batch could
// reject the whole batch.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// Name is the collector name and batch source.
const Name = "docker"

// MinInterval is the smallest permitted polling interval.
const MinInterval = 30 * time.Second

// DefaultSocket is used when DOCKER_HOST is unset or not a unix:// URL.
const DefaultSocket = "/var/run/docker.sock"

var _ collectors.Collector = (*Collector)(nil)

// Collector implements collectors.Collector for Docker.
type Collector struct {
	socket   string
	interval time.Duration
	client   *http.Client
	now      func() time.Time
}

// Option customizes a Collector.
type Option func(*Collector)

// WithSocket overrides the socket path.
func WithSocket(p string) Option { return func(c *Collector) { c.socket = p } }

// WithInterval sets the polling interval (clamped to MinInterval).
func WithInterval(d time.Duration) Option { return func(c *Collector) { c.interval = d } }

// WithClock overrides the time source.
func WithClock(now func() time.Time) Option { return func(c *Collector) { c.now = now } }

// SocketPath resolves the socket from DOCKER_HOST (unix://) or the default.
func SocketPath() string {
	if h := os.Getenv("DOCKER_HOST"); strings.HasPrefix(h, "unix://") {
		if p := strings.TrimPrefix(h, "unix://"); p != "" {
			return p
		}
	}
	return DefaultSocket
}

// New builds a Docker collector.
func New(opts ...Option) *Collector {
	c := &Collector{socket: SocketPath(), interval: MinInterval, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	if c.interval < MinInterval {
		c.interval = MinInterval
	}
	sock := c.socket
	c.client = &http.Client{Transport: getOnly{&http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}}}
	return c
}

// Name implements collectors.Collector.
func (c *Collector) Name() string { return Name }

// Interval implements collectors.Collector.
func (c *Collector) Interval() time.Duration { return c.interval }

// getOnly refuses every request that is not a GET.
type getOnly struct{ rt http.RoundTripper }

func (g getOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		return nil, fmt.Errorf("docker: %s refused: collector is read-only", r.Method)
	}
	return g.rt.RoundTrip(r)
}

func (c *Collector) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker: GET %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// absent reports whether err means there is no Docker socket to talk to.
func absent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) ||
		isConnRefused(err)
}

func isConnRefused(err error) bool {
	var ne *net.OpError
	return errors.As(err, &ne) && strings.Contains(ne.Err.Error(), "connection refused")
}

type listedContainer struct {
	ID string `json:"Id"`
}

type inspectedContainer struct {
	ID     string                  `json:"Id"`
	Name   string                  `json:"Name"`
	Image  string                  `json:"Image"`
	State  struct{ Status string } `json:"State"`
	Config struct {
		Image  string
		User   string
		Env    []string
		Labels map[string]string
	} `json:"Config"`
	HostConfig struct {
		Privileged  bool
		NetworkMode string
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct{ NetworkID string }
		Ports    map[string][]struct{ HostIP, HostPort string }
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type string
		Name string
	} `json:"Mounts"`
}

type listedImage struct {
	ID       string   `json:"Id"`
	RepoTags []string `json:"RepoTags"`
	Digests  []string `json:"RepoDigests"`
	Size     int64    `json:"Size"`
}

type listedNetwork struct {
	ID     string            `json:"Id"`
	Name   string            `json:"Name"`
	Driver string            `json:"Driver"`
	Scope  string            `json:"Scope"`
	Labels map[string]string `json:"Labels"`
}

type listedVolumes struct {
	Volumes []struct {
		Name   string            `json:"Name"`
		Driver string            `json:"Driver"`
		Labels map[string]string `json:"Labels"`
	} `json:"Volumes"`
}

// Collect implements collectors.Collector.
func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	out := graph.Batch{Collector: Name, ObservedAt: c.now().UTC()}

	if _, err := os.Stat(c.socket); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		if errors.Is(err, fs.ErrPermission) {
			return out, fmt.Errorf("docker: permission denied on %s", c.socket)
		}
		return out, err
	}

	var list []listedContainer
	if err := c.get(ctx, "/containers/json?all=1", &list); err != nil {
		return c.fail(out, err)
	}
	var images []listedImage
	if err := c.get(ctx, "/images/json", &images); err != nil {
		return c.fail(out, err)
	}
	var networks []listedNetwork
	if err := c.get(ctx, "/networks", &networks); err != nil {
		return c.fail(out, err)
	}
	var vols listedVolumes
	if err := c.get(ctx, "/volumes", &vols); err != nil {
		return c.fail(out, err)
	}

	ids := map[string]identity.ID{} // "kind:key" -> entity id
	add := func(kind, key string, id map[string]string, attrs map[string]any) error {
		h, err := identity.Hash(kind, id)
		if err != nil {
			return err
		}
		ids[kind+":"+key] = h
		out.Entities = append(out.Entities, batch.Entity{Type: kind, Identity: id, Attributes: attrs})
		return nil
	}

	for _, im := range images {
		if im.ID == "" {
			continue
		}
		attrs := map[string]any{
			"repo_tags":    sortedCopy(im.RepoTags),
			"repo_digests": sortedCopy(im.Digests),
			"size":         im.Size,
		}
		if k, ok := canonical.Key(canonical.KindImage, im.ID); ok {
			attrs[canonical.AttrCanonicalKey] = k
		}
		if err := add("image", im.ID, map[string]string{"id": im.ID}, attrs); err != nil {
			return out, err
		}
	}
	netByName := map[string]string{}
	for _, n := range networks {
		if n.ID == "" {
			continue
		}
		netByName[n.Name] = n.ID
		if err := add("network", n.ID, map[string]string{"id": n.ID}, map[string]any{
			"name": n.Name, "driver": n.Driver, "scope": n.Scope, "labels": labelList(n.Labels),
		}); err != nil {
			return out, err
		}
	}
	for _, v := range vols.Volumes {
		if v.Name == "" {
			continue
		}
		if err := add("volume", v.Name, map[string]string{"name": v.Name}, map[string]any{
			"driver": v.Driver, "labels": labelList(v.Labels),
		}); err != nil {
			return out, err
		}
	}

	type rel struct{ typ, from, to string }
	var rels []rel
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	for _, lc := range list {
		var ic inspectedContainer
		if err := c.get(ctx, "/containers/"+url.PathEscape(lc.ID)+"/json", &ic); err != nil {
			return c.fail(out, err)
		}
		if ic.ID == "" {
			continue
		}
		img := ic.Config.Image
		keys := envKeys(ic.Config.Env)
		ic.Config.Env = nil // values never leave this function
		if err := add("container", ic.ID, map[string]string{"id": ic.ID}, map[string]any{
			"name":         strings.TrimPrefix(ic.Name, "/"),
			"image_ref":    img,
			"state":        ic.State.Status,
			"ports":        portList(ic.NetworkSettings.Ports),
			"labels":       labelList(ic.Config.Labels),
			"env_keys":     keys,
			"privileged":   ic.HostConfig.Privileged,
			"network_mode": ic.HostConfig.NetworkMode,
			"user":         ic.Config.User,
		}); err != nil {
			return out, err
		}
		cid := ids["container:"+ic.ID]
		if iid, ok := ids["image:"+ic.Image]; ok {
			rels = append(rels, rel{"uses", string(cid), string(iid)})
		}
		for _, n := range ic.NetworkSettings.Networks {
			if nid, ok := ids["network:"+n.NetworkID]; ok {
				rels = append(rels, rel{"attached_to", string(cid), string(nid)})
			}
		}
		for _, m := range ic.Mounts {
			if m.Type != "volume" {
				continue
			}
			if vid, ok := ids["volume:"+m.Name]; ok {
				rels = append(rels, rel{"mounts", string(cid), string(vid)})
			}
		}
	}
	seen := map[rel]bool{}
	for _, r := range rels {
		if seen[r] {
			continue
		}
		seen[r] = true
		out.Relations = append(out.Relations, batch.Relation{Type: r.typ, From: r.from, To: r.to})
	}
	return out, nil
}

// fail maps a transport error: a vanished/refusing socket is "absent".
func (c *Collector) fail(out graph.Batch, err error) (graph.Batch, error) {
	if absent(err) {
		return graph.Batch{Collector: Name, ObservedAt: out.ObservedAt}, nil
	}
	if errors.Is(err, fs.ErrPermission) {
		return graph.Batch{}, fmt.Errorf("docker: permission denied on %s", c.socket)
	}
	return graph.Batch{}, err
}

func envKeys(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func labelList(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func portList(m map[string][]struct{ HostIP, HostPort string }) []string {
	out := []string{}
	for p, binds := range m {
		if len(binds) == 0 {
			out = append(out, p)
			continue
		}
		for _, b := range binds {
			out = append(out, b.HostIP+":"+b.HostPort+"->"+p)
		}
	}
	sort.Strings(out)
	return out
}
