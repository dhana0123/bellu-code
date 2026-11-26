package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/retry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/kubernetes/k8sschema"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

const (
	defaultInterval = 5 * time.Minute
	pageLimit       = 500
	maxPageBody     = 32 << 20
	// maxItemsPerType caps one resource type; beyond it the type is truncated.
	maxItemsPerType = 20000

	// metadataAccept makes the API server return only object metadata, so
	// Secret and ConfigMap values never cross the wire (Requirement 14.6).
	metadataAccept = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
	jsonAccept     = "application/json"
	partialKind    = "PartialObjectMetadataList"

	clusterNamespace = "kube-system" // its UID identifies the cluster
)

type collector struct {
	hc         *http.Client
	host       string // API server host[:port]
	connID     string
	interval   time.Duration
	namespaces map[string]bool // empty selects every namespace
	status     collectors.StatusRecorder
	sleep      func(ctx context.Context, d time.Duration) error // nil: real waits
	probeSleep func(ctx context.Context, d time.Duration) error
}

var (
	_ collectors.StatusReporter = (*collector)(nil)
	_ collectors.Timeouter      = (*collector)(nil)
)

// NewCollector returns the collector of one Kubernetes Connection. hc must be
// the broker client of the connection and host its API server (host[:port]).
// Selection.Items limits the namespaces read.
func NewCollector(hc *http.Client, host string, conn store.Connection, sel store.Selection) collectors.Collector {
	iv := defaultInterval
	if conn.IntervalSec > 0 {
		iv = time.Duration(conn.IntervalSec) * time.Second
	}
	ns := map[string]bool{}
	for _, n := range sel.Items {
		ns[n] = true
	}
	return &collector{hc: hc, host: host, connID: conn.ID, interval: iv, namespaces: ns}
}

func (c *collector) Name() string                    { return "connector:kubernetes:" + c.connID }
func (c *collector) Interval() time.Duration         { return c.interval }
func (c *collector) Timeout() time.Duration          { return collectors.ConnectorTimeout }
func (c *collector) RunStatus() collectors.RunStatus { return c.status.Status() }

// httpError is a non-2xx answer. HTTPStatus lets collectors.ClassifyGap and the
// supervisor read the code.
type httpError struct {
	code int
	path string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("kubernetes: GET %s: status %d", e.path, e.code)
}
func (e *httpError) HTTPStatus() int { return e.code }

// resourceType is one row of the collection table. Each row fails on its own.
type resourceType struct {
	name         string
	path         string
	metadataOnly bool // listed as PartialObjectMetadataList
	clusterScope bool
	kind         string
	workload     string // workload_kind value
	roleKind     string // "Role" or "ClusterRole" for role types
	binding      bool
}

var resourceTypes = []resourceType{
	{name: "nodes", path: "/api/v1/nodes", clusterScope: true, kind: k8sschema.KindNode},
	{name: "pods", path: "/api/v1/pods", kind: k8sschema.KindPod},
	{name: "deployments", path: "/apis/apps/v1/deployments", kind: k8sschema.KindWorkload, workload: k8sschema.TypeDeployment},
	{name: "statefulsets", path: "/apis/apps/v1/statefulsets", kind: k8sschema.KindWorkload, workload: k8sschema.TypeStatefulSet},
	{name: "daemonsets", path: "/apis/apps/v1/daemonsets", kind: k8sschema.KindWorkload, workload: k8sschema.TypeDaemonSet},
	{name: "replicasets", path: "/apis/apps/v1/replicasets", kind: k8sschema.KindWorkload, workload: k8sschema.TypeReplicaSet},
	{name: "jobs", path: "/apis/batch/v1/jobs", kind: k8sschema.KindWorkload, workload: k8sschema.TypeJob},
	{name: "cronjobs", path: "/apis/batch/v1/cronjobs", kind: k8sschema.KindWorkload, workload: k8sschema.TypeCronJob},
	{name: "services", path: "/api/v1/services", kind: k8sschema.KindService},
	{name: "ingresses", path: "/apis/networking.k8s.io/v1/ingresses", kind: k8sschema.KindIngress},
	{name: "networkpolicies", path: "/apis/networking.k8s.io/v1/networkpolicies", kind: k8sschema.KindNetPol},
	{name: "serviceaccounts", path: "/api/v1/serviceaccounts", kind: k8sschema.KindServiceAccount},
	{name: "roles", path: "/apis/rbac.authorization.k8s.io/v1/roles", kind: k8sschema.KindRole, roleKind: "Role"},
	{name: "clusterroles", path: "/apis/rbac.authorization.k8s.io/v1/clusterroles", clusterScope: true, kind: k8sschema.KindRole, roleKind: "ClusterRole"},
	{name: "rolebindings", path: "/apis/rbac.authorization.k8s.io/v1/rolebindings", kind: k8sschema.KindBinding, binding: true},
	{name: "clusterrolebindings", path: "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", clusterScope: true, kind: k8sschema.KindBinding, binding: true},
	{name: "secrets", path: "/api/v1/secrets", metadataOnly: true, kind: k8sschema.KindSecretRef},
	{name: "configmaps", path: "/api/v1/configmaps", metadataOnly: true, kind: k8sschema.KindConfigMapRef},
}

// object is the subset of a Kubernetes object that is read. It declares no
// field that could hold a Secret or ConfigMap value.
type object struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		UID               string            `json:"uid"`
		CreationTimestamp string            `json:"creationTimestamp"`
		Labels            map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName string        `json:"serviceAccountName"`
		NodeName           string        `json:"nodeName"`
		Containers         []container   `json:"containers"`
		Type               string        `json:"type"`
		ClusterIP          string        `json:"clusterIP"`
		Ports              []servicePort `json:"ports"`
		Template           *struct {
			Spec struct {
				ServiceAccountName string      `json:"serviceAccountName"`
				Containers         []container `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Rules   []json.RawMessage `json:"rules"`
	RoleRef struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
	Subjects []struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"subjects"`
}

type container struct {
	Image string `json:"image"`
}

type servicePort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type list struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []object `json:"items"`
}

// Collect reads every selected resource type. A type that fails becomes a gap
// and the run returns collectors.PartialError with the batch of the others.
func (c *collector) Collect(ctx context.Context) (graph.Batch, error) {
	c.status.Reset()
	ctx = broker.WithWaitObserver(ctx, func(w broker.RateWait) { c.status.Wait("cluster", w.Until, w.Waited) })

	if err := c.probe(ctx); err != nil {
		return graph.Batch{}, err
	}

	// Namespaces first: the kube-system UID identifies the cluster.
	nsObjs, err := c.listAll(ctx, "/api/v1/namespaces", false)
	if err != nil {
		c.status.FailType("namespaces", "cluster", err)
		return graph.Batch{}, fmt.Errorf("kubernetes: namespaces: %w", err)
	}
	clusterUID := ""
	for _, o := range nsObjs {
		if o.Metadata.Name == clusterNamespace {
			clusterUID = o.Metadata.UID
		}
	}
	if clusterUID == "" {
		return graph.Batch{}, errors.New("kubernetes: cannot read the uid of namespace " + clusterNamespace)
	}

	b := &builder{c: c, cluster: clusterUID, seen: map[string]string{}}
	b.b.Collector = c.Name()
	clusterIdn := map[string]string{"connection": c.connID, "uid": clusterUID}
	cid, err := identity.Hash(k8sschema.KindCluster, clusterIdn)
	if err != nil {
		return graph.Batch{}, err
	}
	b.clusterID = string(cid)
	b.b.Entities = append(b.b.Entities, batch.Entity{Type: k8sschema.KindCluster, Identity: clusterIdn,
		Attributes: map[string]any{"connection": c.connID, "uid": clusterUID, "api_host": c.host, "source": c.Name()}})
	for _, o := range nsObjs {
		if len(c.namespaces) > 0 && !c.namespaces[o.Metadata.Name] {
			continue
		}
		b.add(k8sschema.KindNamespace, "ns/"+o.Metadata.Name, o, nil)
	}

	var failed []string
	for _, rt := range resourceTypes {
		objs, err := c.listAll(ctx, rt.path, rt.metadataOnly)
		if err != nil {
			if ctx.Err() != nil {
				return graph.Batch{}, ctx.Err()
			}
			c.status.FailType(rt.name, "cluster", err)
			failed = append(failed, rt.name)
			b.retain(rt)
			continue
		}
		for _, o := range objs {
			if !rt.clusterScope && len(c.namespaces) > 0 && !c.namespaces[o.Metadata.Namespace] {
				continue
			}
			b.object(rt, o)
		}
	}
	if len(failed) == len(resourceTypes) {
		// An empty full observation would delete every entity.
		return graph.Batch{}, errors.New("kubernetes: every resource type failed")
	}
	b.resolve()
	if len(failed) > 0 {
		sort.Strings(failed)
		return b.b, collectors.PartialError{Types: failed}
	}
	return b.b, nil
}

// probe reads /version at the start of a run. Three consecutive failures end
// the run before anything is collected, so the graph keeps its data.
func (c *collector) probe(ctx context.Context) error {
	var opts []collectors.ProbeOption
	if c.probeSleep != nil {
		opts = append(opts, collectors.WithProbeSleep(c.probeSleep))
	}
	err := collectors.Probe(ctx, func(ctx context.Context) error {
		_, err := c.get(ctx, "/version", jsonAccept)
		return err
	}, opts...)
	var pe *collectors.ProbeError
	if !errors.As(err, &pe) {
		return err
	}
	if pe.Kind == collectors.ProbeCredentialsRejected {
		c.status.Auth("provider rejected the credentials")
		code := lifecycle.StatusUnauthorized
		var hs interface{ HTTPStatus() int }
		if errors.As(pe.Err, &hs) {
			code = hs.HTTPStatus()
		}
		return fmt.Errorf("%w: %w", &lifecycle.HTTPStatusError{Code: code}, pe)
	}
	return pe
}

// listAll pages through one collection. A metadata-only list must come back as
// PartialObjectMetadataList; anything else is discarded unread so values that a
// server sent anyway are never kept.
func (c *collector) listAll(ctx context.Context, path string, metadataOnly bool) ([]object, error) {
	accept := jsonAccept
	if metadataOnly {
		accept = metadataAccept
	}
	var out []object
	cont := ""
	for {
		q := url.Values{"limit": {fmt.Sprint(pageLimit)}}
		if cont != "" {
			q.Set("continue", cont)
		}
		body, err := c.get(ctx, path+"?"+q.Encode(), accept)
		if err != nil {
			return nil, err
		}
		var l list
		if err := json.Unmarshal(body, &l); err != nil {
			return nil, fmt.Errorf("kubernetes: GET %s: malformed response", path)
		}
		if metadataOnly && l.Kind != partialKind {
			return nil, fmt.Errorf("kubernetes: GET %s: server did not return %s", path, partialKind)
		}
		out = append(out, l.Items...)
		if len(out) >= maxItemsPerType {
			c.status.Truncate(path, len(out)-maxItemsPerType)
			return out[:maxItemsPerType], nil
		}
		if cont = l.Metadata.Continue; cont == "" {
			return out, nil
		}
	}
}

// get sends one GET through the broker client, retrying rate limits.
func (c *collector) get(ctx context.Context, pathQuery, accept string) ([]byte, error) {
	var body []byte
	opts := []retry.Option{retry.WithOnWait(func(d time.Duration) {
		c.status.Wait("cluster", time.Now().Add(d), d)
	})}
	if c.sleep != nil {
		opts = append(opts, retry.WithSleep(c.sleep))
	}
	err := retry.Do(ctx, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.host+pathQuery, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", accept)
		resp, err := c.hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if rl := retry.FromResponse(resp, time.Now()); rl != nil {
			return rl
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			path, _, _ := strings.Cut(pathQuery, "?")
			return &httpError{code: resp.StatusCode, path: path}
		}
		body, err = io.ReadAll(io.LimitReader(resp.Body, maxPageBody))
		return err
	}, opts...)
	return body, err
}

type builder struct {
	c         *collector
	cluster   string
	clusterID string
	b         batch.Batch
	seen      map[string]string // key -> entity id
	pending   []pendingRel
}

// pendingRel is resolved after every type ran, so a relation never names an
// entity that was not collected.
type pendingRel struct{ typ, from, to string }

func (b *builder) rel(typ, from, to string) { b.pending = append(b.pending, pendingRel{typ, from, to}) }

func (b *builder) resolve() {
	for _, p := range b.pending {
		f, ok1 := b.seen[p.from]
		t, ok2 := b.seen[p.to]
		if ok1 && ok2 {
			b.b.Relations = append(b.b.Relations, batch.Relation{Type: p.typ, From: f, To: t})
		}
	}
}

// add records one entity. The Entity_ID depends on the API server uid only, so
// a rename or label change keeps it.
func (b *builder) add(kind, key string, o object, extra map[string]any) {
	if o.Metadata.UID == "" {
		return
	}
	idn := map[string]string{"connection": b.c.connID, "cluster": b.cluster, "uid": o.Metadata.UID}
	id, err := identity.Hash(kind, idn)
	if err != nil {
		return
	}
	a := map[string]any{
		"connection": b.c.connID, "cluster": b.cluster, "uid": o.Metadata.UID, "source": b.c.Name(),
		"name": o.Metadata.Name, "namespace": o.Metadata.Namespace, "created_at": o.Metadata.CreationTimestamp,
	}
	for k, v := range extra {
		a[k] = v
	}
	b.b.Entities = append(b.b.Entities, batch.Entity{Type: kind, Identity: idn, Attributes: a})
	b.seen[key] = string(id)
}

func (b *builder) object(rt resourceType, o object) {
	podSpec := o.Spec.ServiceAccountName
	containers := o.Spec.Containers
	if o.Spec.Template != nil {
		podSpec, containers = o.Spec.Template.Spec.ServiceAccountName, o.Spec.Template.Spec.Containers
	}
	extra := map[string]any{}
	switch rt.kind {
	case k8sschema.KindWorkload:
		extra[k8sschema.DiscriminatorWorkloadKind] = rt.workload
	case k8sschema.KindService:
		extra["service_type"], extra["cluster_ip"] = o.Spec.Type, o.Spec.ClusterIP
		ports := make([]string, 0, len(o.Spec.Ports))
		for _, p := range o.Spec.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
		}
		extra["ports"] = ports
	case k8sschema.KindPod:
		extra["node_name"] = o.Spec.NodeName
	case k8sschema.KindRole:
		extra["role_kind"], extra["rule_count"] = rt.roleKind, len(o.Rules)
	case k8sschema.KindBinding:
		extra["role_ref"] = o.RoleRef.Kind + "/" + o.RoleRef.Name
	}
	if rt.kind == k8sschema.KindPod || rt.kind == k8sschema.KindWorkload {
		imgs := make([]string, 0, len(containers))
		for _, ct := range containers {
			imgs = append(imgs, ct.Image)
		}
		extra["images"] = imgs
		for _, img := range imgs {
			if engine := databaseEngine(img); engine != "" {
				extra["data_store"], extra["database_engine"] = "true", engine
				break
			}
		}
	}

	key := rt.kind + "/" + o.Metadata.UID
	b.add(rt.kind, key, o, extra)
	if _, ok := b.seen[key]; !ok {
		return
	}
	if !rt.clusterScope {
		b.rel(k8sschema.RelInNamespace, key, "ns/"+o.Metadata.Namespace)
	}
	switch rt.kind {
	case k8sschema.KindServiceAccount:
		b.seen["sa/"+o.Metadata.Namespace+"/"+o.Metadata.Name] = b.seen[key]
	case k8sschema.KindRole:
		b.seen[roleKey(rt.roleKind, o.Metadata.Namespace, o.Metadata.Name)] = b.seen[key]
	case k8sschema.KindPod, k8sschema.KindWorkload:
		if podSpec == "" {
			podSpec = "default"
		}
		b.rel(k8sschema.RelRunsAsSA, key, "sa/"+o.Metadata.Namespace+"/"+podSpec)
	case k8sschema.KindBinding:
		ns := o.Metadata.Namespace
		for _, s := range o.Subjects {
			if s.Kind != "ServiceAccount" {
				continue
			}
			sns := s.Namespace
			if sns == "" {
				sns = ns
			}
			b.rel(k8sschema.RelBoundTo, "sa/"+sns+"/"+s.Name, roleKey(o.RoleRef.Kind, ns, o.RoleRef.Name))
		}
	}
}

// roleKey names a Role in its namespace or a ClusterRole cluster wide. A
// RoleBinding may reference either.
func roleKey(kind, ns, name string) string {
	if kind == "ClusterRole" {
		return "role//" + name
	}
	return "role/" + ns + "/" + name
}

// retain keeps what a failed type held in the previous run, because a full
// observation would otherwise retire it.
func (b *builder) retain(rt resourceType) {
	r := batch.Retain{Kind: rt.kind}
	if rt.workload != "" {
		r.Attrs = map[string]string{k8sschema.DiscriminatorWorkloadKind: rt.workload}
	}
	if rt.roleKind != "" {
		r.Attrs = map[string]string{"role_kind": rt.roleKind}
	}
	b.b.Retain = append(b.b.Retain, r)
}

// databaseImages lists image repository names that run a database.
var databaseImages = map[string]bool{
	"postgres": true, "postgresql": true, "mysql": true, "mariadb": true, "mongo": true, "mongodb": true,
	"redis": true, "memcached": true, "cassandra": true, "couchdb": true, "couchbase": true,
	"cockroach": true, "clickhouse-server": true, "influxdb": true, "elasticsearch": true,
	"opensearch": true, "neo4j": true, "mssql-server": true, "etcd": true, "valkey": true,
}

// databaseEngine returns the repository name when image is a known database
// image, or an empty string. The registry host, tag and digest are ignored.
func databaseEngine(image string) string {
	ref, _, _ := strings.Cut(image, "@")
	ref = ref[strings.LastIndex(ref, "/")+1:]
	name, _, _ := strings.Cut(ref, ":")
	name = strings.ToLower(name)
	if databaseImages[name] {
		return name
	}
	return ""
}
