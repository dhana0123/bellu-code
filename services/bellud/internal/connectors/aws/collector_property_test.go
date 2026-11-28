package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// propClient is a fixture-driven Client that records every call.
type propClient struct {
	noNetwork
	mu      sync.Mutex
	regions []string // regions the fixture knows (selected or not)
	perType int      // resources per type per region
	buckets []Bucket
	roles   int
	fail    map[string]bool
	names   []string // arbitrary strings used for name-like fields
	calls   []string // "<op>:<region>"
}

func (p *propClient) rec(op, region string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, op+":"+region)
	if p.fail[op] {
		return ErrAccessDenied
	}
	return nil
}

func (p *propClient) name(i int) string { return p.names[i%len(p.names)] }

func (p *propClient) Identity(context.Context) (Identity, error) {
	return Identity{Account: "123456789012"}, nil
}
func (p *propClient) SimulateWrites(context.Context, string, []string) ([]AllowedAction, error) {
	return nil, nil
}
func (p *propClient) Regions(context.Context) ([]string, error) { return p.regions, nil }
func (p *propClient) Instances(_ context.Context, r string) (Listing[Instance], error) {
	if err := p.rec("ec2", r); err != nil {
		return Listing[Instance]{}, err
	}
	var out []Instance
	for i := 0; i < p.perType; i++ {
		out = append(out, Instance{ID: fmt.Sprintf("i-%d", i), Region: r, Name: p.name(i), State: "running",
			Type: "t3.micro", VPCID: "vpc-0", SecurityGroupIDs: []string{"sg-0"}, LaunchTime: time.Unix(1700000000, 0), TagCount: i})
	}
	return Listing[Instance]{Items: out}, nil
}
func (p *propClient) Buckets(context.Context) ([]Bucket, error) {
	if err := p.rec("s3", ""); err != nil {
		return nil, err
	}
	return p.buckets, nil
}
func (p *propClient) SecurityGroups(_ context.Context, r string) (Listing[SecurityGroup], error) {
	if err := p.rec("security-groups", r); err != nil {
		return Listing[SecurityGroup]{}, err
	}
	var out []SecurityGroup
	for i := 0; i < p.perType; i++ {
		out = append(out, SecurityGroup{ID: fmt.Sprintf("sg-%d", i), Region: r, Name: p.name(i), VPCID: "vpc-0"})
	}
	return Listing[SecurityGroup]{Items: out}, nil
}
func (p *propClient) VPCs(_ context.Context, r string) (Listing[VPC], error) {
	if err := p.rec("vpc", r); err != nil {
		return Listing[VPC]{}, err
	}
	var out []VPC
	for i := 0; i < p.perType; i++ {
		out = append(out, VPC{ID: fmt.Sprintf("vpc-%d", i), Region: r, Name: p.name(i), State: "available"})
	}
	return Listing[VPC]{Items: out}, nil
}
func (p *propClient) Roles(context.Context) ([]Role, error) {
	if err := p.rec("iam", ""); err != nil {
		return nil, err
	}
	var out []Role
	for i := 0; i < p.roles; i++ {
		out = append(out, Role{ARN: fmt.Sprintf("arn:aws:iam::123456789012:role/r%d", i), Name: p.name(i)})
	}
	return out, nil
}
func (p *propClient) Functions(_ context.Context, r string) ([]Function, error) {
	if err := p.rec("lambda", r); err != nil {
		return nil, err
	}
	var out []Function
	for i := 0; i < p.perType; i++ {
		out = append(out, Function{ARN: fmt.Sprintf("arn:aws:lambda:%s:123456789012:function:f%d", r, i), Name: p.name(i), Region: r, Runtime: "go1.x"})
	}
	return out, nil
}
func (p *propClient) DBInstances(_ context.Context, r string) ([]DBInstance, error) {
	if err := p.rec("rds", r); err != nil {
		return nil, err
	}
	var out []DBInstance
	for i := 0; i < p.perType; i++ {
		out = append(out, DBInstance{ARN: fmt.Sprintf("arn:aws:rds:%s:123456789012:db:d%d", r, i), ID: fmt.Sprintf("d%d", i), Region: r, Engine: "postgres", Status: "available"})
	}
	return out, nil
}

var (
	regionPool = []string{"us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1", "ap-northeast-1", "cn-north-1", "us-gov-west-1"}
	// typeNames lists every collector step that calls the API on its own.
	// Per-parent steps (listener, target-health) call nothing without parents
	// and fail only through their dependency.
	typeNames = func() []string {
		var out []string
		for _, s := range collectSteps {
			if len(s.deps) == 0 {
				out = append(out, s.name)
			}
		}
		return out
	}()
	// resource_type attribute produced by each collected type.
	typeResource = map[string]string{"vpc": "ec2:vpc", "security-groups": "ec2:security-group", "ec2": "ec2:instance",
		"s3": "s3:bucket", "iam": "iam:role", "lambda": "lambda:function", "rds": "rds:instance"}
	// Same fragments as the graph's secret-name rule (bge/ident.IsSecretName).
	secretFragments = []string{"secret", "token", "password", "passwd", "credential", "private", "apikey", "api_key", "hash"}
	allowedAttrs    = map[string]bool{
		"connection": true, "arn": true, "source": true, "service": true, "resource_type": true, "region": true,
		"name": true, "state": true, "tag_count": true, "instance_type": true, "created_at": true,
		"runtime": true, "engine": true, "account_id": true, "alias": true, "regions": true,
		"canonical_key": true, "internet_exposed": true,
		"encryption_at_rest": true, "encryption_in_transit": true, "public_access": true, "backup": true, "logging": true, "missing_data": true,
	}
)

func isSecretName(n string) bool {
	l := strings.ToLower(n)
	for _, f := range secretFragments {
		if strings.Contains(l, f) {
			return true
		}
	}
	return false
}

func genSelection(t *rapid.T) []string {
	return rapid.SliceOfNDistinct(rapid.SampledFrom(regionPool), 1, 4, func(s string) string { return s }).Draw(t, "selection")
}

func genClient(t *rapid.T, selected []string) *propClient {
	nb := rapid.IntRange(0, 6).Draw(t, "buckets")
	var bs []Bucket
	for i := 0; i < nb; i++ {
		bs = append(bs, Bucket{Name: fmt.Sprintf("b%d-%s", i, rapid.StringMatching(`[a-z0-9]{0,8}`).Draw(t, "bname")),
			Region: rapid.SampledFrom(regionPool).Draw(t, "bregion")})
	}
	p := &propClient{
		regions: regionPool,
		perType: rapid.IntRange(0, 3).Draw(t, "perType"),
		buckets: bs,
		roles:   rapid.IntRange(0, 3).Draw(t, "roles"),
		// Arbitrary text (including secret/content look-alikes) in name-like fields.
		names: rapid.SliceOfN(rapid.String(), 1, 4).Draw(t, "names"),
		fail:  map[string]bool{},
	}
	p.noNetwork.rec = p.rec
	return p
}

func newPropCollector(c Client, regions []string) collectors.Collector {
	return NewCollector(c, store.Connection{ID: "conn-1", Alias: "prod"}, store.Selection{Regions: regions})
}

// Feature: cloud-connectors, Property 28: Collector output hygiene
//
// **Validates: Requirements 7.8, 7.13**
func TestPropertyAWSCollectorOutputHygiene(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sel := genSelection(t)
		pc := genClient(t, sel)
		b, err := newPropCollector(pc, sel).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if b.Collector != "connector:aws:conn-1" {
			t.Fatalf("collector %q", b.Collector)
		}
		for _, e := range b.Entities {
			if e.Type != "aws_account" && e.Type != "aws_resource" && e.Type != "aws_sg_rule" && e.Type != "aws_cidr" {
				t.Fatalf("unregistered kind %q", e.Type)
			}
			if e.Attributes["source"] != "connector:aws:conn-1" {
				t.Fatalf("missing source tag: %+v", e)
			}
			if e.Identity["connection"] != "conn-1" {
				t.Fatalf("identity lacks connection id: %+v", e)
			}
			for k := range e.Attributes {
				if isSecretName(k) {
					t.Fatalf("secret-like attribute name %q", k)
				}
				if !allowedAttrs[k] {
					t.Fatalf("unexpected attribute %q (metadata only)", k)
				}
			}
			for k := range e.Identity {
				if isSecretName(k) {
					t.Fatalf("secret-like identity key %q", k)
				}
			}
		}
		for _, r := range b.Relations {
			if r.Type == "attached_to" || (r.Type != "owned_by" && r.Type != "runs_on" && !strings.HasPrefix(r.Type, "aws_")) {
				t.Fatalf("unexpected relation %q", r.Type)
			}
		}
	})
}

// Feature: cloud-connectors, Property 32: Selection confinement (regions)
//
// **Validates: Requirements 3.11**
func TestPropertyAWSCollectorSelectionConfinement(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sel := genSelection(t)
		pc := genClient(t, sel)
		b, err := newPropCollector(pc, sel).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		in := map[string]bool{}
		for _, r := range sel {
			in[r] = true
		}
		for _, call := range pc.calls {
			i := strings.IndexByte(call, ':')
			if reg := call[i+1:]; reg != "" && !in[reg] {
				t.Fatalf("call %q outside selection %v", call, sel)
			}
		}
		wantBuckets := 0
		for _, k := range pc.buckets {
			if in[k.Region] {
				wantBuckets++
			}
		}
		gotBuckets := 0
		for _, e := range b.Entities {
			reg, _ := e.Attributes["region"].(string)
			if e.Type == "aws_resource" && reg != "" && !in[reg] {
				t.Fatalf("entity in unselected region: %+v", e.Attributes)
			}
			if e.Attributes["resource_type"] == "s3:bucket" {
				gotBuckets++
			}
		}
		if gotBuckets != wantBuckets {
			t.Fatalf("buckets: got %d want %d", gotBuckets, wantBuckets)
		}
	})
}

// Feature: cloud-connectors, Property 33: Partial failure isolation
//
// **Validates: Requirements 10.4**
func TestPropertyAWSCollectorPartialFailureIsolation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sel := genSelection(t)
		pc := genClient(t, sel)
		failing := rapid.SliceOfNDistinct(rapid.SampledFrom(typeNames), 0, len(typeNames), func(s string) string { return s }).Draw(t, "failing")
		for _, f := range failing {
			pc.fail[f] = true
		}
		b, err := newPropCollector(pc, sel).Collect(context.Background())

		if len(failing) == len(typeNames) {
			var pe collectors.PartialError
			if err == nil || errors.As(err, &pe) {
				t.Fatalf("all failed must be a hard error, got %v", err)
			}
			return
		}
		if len(failing) == 0 {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			var pe collectors.PartialError
			if !errors.As(err, &pe) {
				t.Fatalf("want PartialError, got %v", err)
			}
			// A step whose dependency failed cannot observe and is reported too.
			fs := map[string]bool{}
			for _, f := range failing {
				fs[f] = true
			}
			for _, s := range collectSteps {
				for _, d := range s.deps {
					if fs[d] {
						fs[s.name] = true
					}
				}
			}
			var want []string
			for f := range fs {
				want = append(want, f)
			}
			sort.Strings(want)
			if strings.Join(pe.Types, ",") != strings.Join(want, ",") {
				t.Fatalf("reported %v want %v", pe.Types, want)
			}
		}
		got := map[string]int{}
		hasAccount := false
		for _, e := range b.Entities {
			if e.Type == "aws_account" {
				hasAccount = true
			}
			if rt, ok := e.Attributes["resource_type"].(string); ok {
				got[rt]++
			}
		}
		if !hasAccount {
			t.Fatal("account entity missing")
		}
		inSel := map[string]bool{}
		for _, r := range sel {
			inSel[r] = true
		}
		nb := 0
		for _, k := range pc.buckets {
			if inSel[k.Region] {
				nb++
			}
		}
		expect := map[string]int{
			"vpc": pc.perType * len(sel), "security-groups": pc.perType * len(sel), "ec2": pc.perType * len(sel),
			"lambda": pc.perType * len(sel), "rds": pc.perType * len(sel), "s3": nb, "iam": pc.roles,
		}
		for _, typ := range typeNames {
			if pc.fail[typ] {
				if got[typeResource[typ]] != 0 {
					t.Fatalf("failed type %s produced entities", typ)
				}
				continue
			}
			if got[typeResource[typ]] != expect[typ] {
				t.Fatalf("type %s: got %d entities want %d", typ, got[typeResource[typ]], expect[typ])
			}
		}
	})
}
