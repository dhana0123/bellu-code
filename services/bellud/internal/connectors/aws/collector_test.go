package aws

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

type fakeClient struct {
	noNetwork
	mu    sync.Mutex
	calls []string // "<op>:<region>"
	fail  map[string]bool
}

func (f *fakeClient) rec(op, region string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op+":"+region)
	if f.fail[op] {
		return ErrAccessDenied
	}
	return nil
}

func (f *fakeClient) Identity(context.Context) (Identity, error) {
	return Identity{Account: "123456789012"}, nil
}
func (f *fakeClient) SimulateWrites(context.Context, string, []string) ([]AllowedAction, error) {
	return nil, nil
}
func (f *fakeClient) Regions(context.Context) ([]string, error) { return nil, nil }
func (f *fakeClient) Instances(_ context.Context, r string) (Listing[Instance], error) {
	return Listing[Instance]{Items: []Instance{{ID: "i-1", Region: r, VPCID: "vpc-1", SecurityGroupIDs: []string{"sg-1"}, State: "running"}}}, f.rec("ec2", r)
}
func (f *fakeClient) Buckets(context.Context) ([]Bucket, error) {
	return []Bucket{{Name: "in", Region: "eu-west-1"}, {Name: "out", Region: "ap-south-1"}}, f.rec("s3", "")
}
func (f *fakeClient) SecurityGroups(_ context.Context, r string) (Listing[SecurityGroup], error) {
	return Listing[SecurityGroup]{Items: []SecurityGroup{{ID: "sg-1", Region: r, VPCID: "vpc-1"}}}, f.rec("security-groups", r)
}
func (f *fakeClient) VPCs(_ context.Context, r string) (Listing[VPC], error) {
	return Listing[VPC]{Items: []VPC{{ID: "vpc-1", Region: r}}}, f.rec("vpc", r)
}
func (f *fakeClient) Roles(context.Context) ([]Role, error) {
	return []Role{{ARN: "arn:aws:iam::123456789012:role/r", Name: "r"}}, f.rec("iam", "")
}
func (f *fakeClient) Functions(_ context.Context, r string) ([]Function, error) {
	return []Function{{ARN: "arn:aws:lambda:" + r + ":123456789012:function:f", Name: "f", Region: r}}, f.rec("lambda", r)
}
func (f *fakeClient) DBInstances(_ context.Context, r string) ([]DBInstance, error) {
	return []DBInstance{{ARN: "arn:aws:rds:" + r + ":123456789012:db:d", ID: "d", Region: r}}, f.rec("rds", r)
}

// newFake returns a fakeClient whose network calls are recorded and can fail.
func newFake(fail map[string]bool) *fakeClient {
	f := &fakeClient{fail: fail}
	f.noNetwork.rec = f.rec
	return f
}

func newTestCollector(c Client) collectors.Collector {
	return NewCollector(c, store.Connection{ID: "c1", Alias: "prod"}, store.Selection{Regions: []string{"eu-west-1"}})
}

func TestCollectorIdentityAndOutput(t *testing.T) {
	c := newTestCollector(&fakeClient{})
	if c.Name() != "connector:aws:c1" {
		t.Fatal(c.Name())
	}
	if c.(collectors.Timeouter).Timeout() != 120*time.Second {
		t.Fatal("timeout")
	}
	b, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, e := range b.Entities {
		kinds[e.Type]++
		if e.Attributes["source"] != "connector:aws:c1" || e.Identity["connection"] != "c1" {
			t.Fatalf("bad entity %+v", e)
		}
		if e.Type == "aws_resource" && strings.Contains(e.Identity["arn"], "out") {
			t.Fatal("unselected region bucket collected")
		}
	}
	// account + vpc + sg + instance + bucket(in) + role + lambda + rds
	if kinds["aws_account"] != 1 || kinds["aws_resource"] != 7 {
		t.Fatalf("%v", kinds)
	}
	rel := map[string]int{}
	for _, r := range b.Relations {
		rel[r.Type]++
	}
	if rel["owned_by"] != 7 || rel["runs_on"] != 1 || rel["attached_to"] != 0 || rel["aws_in_vpc"] != 1 {
		t.Fatalf("%v", rel)
	}
}

func TestCollectorOnlySelectedRegions(t *testing.T) {
	f := &fakeClient{}
	if _, err := newTestCollector(f).Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls {
		if i := strings.IndexByte(call, ':'); call[i+1:] != "" && call[i+1:] != "eu-west-1" {
			t.Fatalf("call outside selection: %s", call)
		}
	}
}

func TestCollectorPartialAndRunner(t *testing.T) {
	f := &fakeClient{fail: map[string]bool{"rds": true, "lambda": true}}
	c := newTestCollector(f)
	_, err := c.Collect(context.Background())
	var pe collectors.PartialError
	if !errors.As(err, &pe) || strings.Join(pe.Types, ",") != "lambda,rds" {
		t.Fatalf("%v", err)
	}

	e, oerr := graph.Open(context.Background(), graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if oerr != nil {
		t.Fatal(oerr)
	}
	t.Cleanup(func() { e.Close(context.Background()) })
	if err := collectors.New(e, []collectors.Collector{c}).RunOnce(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Hash("aws_account", map[string]string{"connection": "c1", "account_id": "123456789012"})
	if _, err := e.Query().Entity(context.Background(), graph.EntityID(id), nil); err != nil {
		t.Fatalf("account not ingested: %v", err)
	}
	sid, _ := identity.Hash("collector_status", map[string]string{"collector": c.Name()})
	st, err := e.Query().Entity(context.Background(), graph.EntityID(sid), nil)
	if err != nil || st.Attributes["status"] != collectors.StatusOK || st.Attributes["last_error"] != "partial: lambda,rds" {
		t.Fatalf("%v %v", st.Attributes, err)
	}
}

func TestCollectorNoRegionAndAllFailed(t *testing.T) {
	c := NewCollector(&fakeClient{}, store.Connection{ID: "c1"}, store.Selection{})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("expected error without regions")
	}
	all := map[string]bool{}
	for _, s := range collectSteps {
		all[s.name] = true
	}
	b, err := newTestCollector(newFake(all)).Collect(context.Background())
	var pe collectors.PartialError
	if err == nil || errors.As(err, &pe) || len(b.Entities) != 0 {
		t.Fatalf("%v", err)
	}
}
