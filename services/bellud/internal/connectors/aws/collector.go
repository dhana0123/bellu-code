package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// This file maps Client projections to graph entities. It depends on the
// Client interface only: no SDK and no net/http. Only metadata is collected
// (no object contents, environment variable values or secrets).

const (
	kindAccount  = "aws_account"
	kindResource = "aws_resource"

	defaultInterval = 5 * time.Minute
)

type collector struct {
	client   Client
	connID   string
	alias    string
	interval time.Duration
	regions  []string // selected, deduplicated, sorted
	status   collectors.StatusRecorder
}

var _ collectors.StatusReporter = (*collector)(nil)

// RunStatus implements collectors.StatusReporter. It describes the last
// Collect call: rate-limit waits, the authorization error that ended it, and
// the scopes AWS denied.
func (c *collector) RunStatus() collectors.RunStatus { return c.status.Status() }

// NewCollector returns the collector of one AWS Connection. Only the regions
// in sel are queried.
func NewCollector(c Client, conn store.Connection, sel store.Selection) collectors.Collector {
	seen := map[string]bool{}
	var rs []string
	for _, r := range sel.Regions {
		if r = strings.TrimSpace(r); r != "" && !seen[r] {
			seen[r] = true
			rs = append(rs, r)
		}
	}
	sort.Strings(rs)
	iv := defaultInterval
	if conn.IntervalSec > 0 {
		iv = time.Duration(conn.IntervalSec) * time.Second
	}
	return &collector{client: c, connID: conn.ID, alias: conn.Alias, interval: iv, regions: rs}
}

func (c *collector) Name() string            { return "connector:aws:" + c.connID }
func (c *collector) Interval() time.Duration { return c.interval }

// Timeout implements collectors.Timeouter.
func (c *collector) Timeout() time.Duration { return collectors.ConnectorTimeout }

func partition(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	}
	return "aws"
}

type builder struct {
	c       *collector
	source  string
	account string
	acctID  string
	b       batch.Batch
	seen    map[string]string // arn -> entity id
}

func (b *builder) add(arn, service, rtype, region string, attrs map[string]any) (string, bool) {
	if arn == "" {
		return "", false
	}
	if id, ok := b.seen[arn]; ok {
		return id, true
	}
	idn := map[string]string{"connection": b.c.connID, "arn": arn}
	id, err := identity.Hash(kindResource, idn)
	if err != nil {
		return "", false
	}
	a := map[string]any{
		"connection": b.c.connID, "arn": arn, "source": b.source,
		"service": service, "resource_type": rtype, "region": region,
	}
	for k, v := range attrs {
		a[k] = v
	}
	if key, ok := canonical.Key(canonical.KindARN, arn); ok {
		a[canonical.AttrCanonicalKey] = key
	}
	b.b.Entities = append(b.b.Entities, batch.Entity{Type: kindResource, Identity: idn, Attributes: a})
	b.b.Relations = append(b.b.Relations, batch.Relation{Type: "owned_by", From: string(id), To: b.account})
	b.seen[arn] = string(id)
	return string(id), true
}

// exposed reports whether the instance has a public address and at least one
// attached security group open to the internet. Groups not attached to the
// instance are ignored.
func exposed(i Instance, groups []SecurityGroup) bool {
	if i.PublicIP == "" {
		return false
	}
	attached := make(map[string]bool, len(i.SecurityGroupIDs))
	for _, id := range i.SecurityGroupIDs {
		attached[id] = true
	}
	for _, g := range groups {
		if g.OpenToInternet && attached[g.ID] {
			return true
		}
	}
	return false
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Collect gathers the full current observation. A failing resource type is
// skipped and reported through collectors.PartialError.
func (c *collector) Collect(ctx context.Context) (graph.Batch, error) {
	c.status.Reset()
	if len(c.regions) == 0 {
		return graph.Batch{}, errors.New("aws: no region selected")
	}
	ident, err := c.client.Identity(broker.WithWaitObserver(ctx, c.waitObserver("global")))
	if err != nil {
		if isRejected(err) {
			return graph.Batch{}, c.rejected(err)
		}
		return graph.Batch{}, err
	}
	if ident.Account == "" {
		return graph.Batch{}, errors.New("aws: empty account id")
	}
	source := c.Name()
	acctIdn := map[string]string{"connection": c.connID, "account_id": ident.Account}
	acctID, err := identity.Hash(kindAccount, acctIdn)
	if err != nil {
		return graph.Batch{}, err
	}
	b := &builder{c: c, source: source, account: string(acctID), acctID: ident.Account, seen: map[string]string{}}
	b.b.Collector = source
	b.b.Entities = append(b.b.Entities, batch.Entity{Type: kindAccount, Identity: acctIdn, Attributes: map[string]any{
		"connection": c.connID, "account_id": ident.Account, "source": source,
		"alias": c.alias, "regions": strings.Join(c.regions, ","),
	}})

	failed := map[string]bool{}
	attempted := 0
	// rejectedErr is the first credential rejection; it ends the run.
	var rejectedErr error
	// note records a failed type, a denied scope, or a credential rejection.
	note := func(typ, scope string, err error) {
		failed[typ] = true
		switch {
		case isRejected(err):
			if rejectedErr == nil {
				rejectedErr = err
			}
		case errors.Is(err, ErrAccessDenied):
			c.status.Deny(typ + "@" + scope)
		}
	}
	// each runs fn once per selected region and records the type on any error.
	each := func(typ string, fn func(ctx context.Context, region string) error) {
		attempted++
		for _, r := range c.regions {
			if rejectedErr != nil {
				return
			}
			if ctx.Err() != nil {
				failed[typ] = true
				return
			}
			if err := fn(broker.WithWaitObserver(ctx, c.waitObserver(r)), r); err != nil {
				note(typ, r, err)
			}
		}
	}
	once := func(typ string, fn func(ctx context.Context) error) {
		attempted++
		if rejectedErr != nil {
			return
		}
		if ctx.Err() != nil {
			failed[typ] = true
			return
		}
		if err := fn(broker.WithWaitObserver(ctx, c.waitObserver("global"))); err != nil {
			note(typ, "global", err)
		}
	}
	selected := map[string]bool{}
	for _, r := range c.regions {
		selected[r] = true
	}
	acct := ident.Account

	// VPCs and security groups first so instances can relate to them.
	vpcARN := map[string]string{} // region/vpc-id -> entity id
	each("vpc", func(ctx context.Context, r string) error {
		vs, err := c.client.VPCs(ctx, r)
		for _, v := range vs {
			arn := fmt.Sprintf("arn:%s:ec2:%s:%s:vpc/%s", partition(r), r, acct, v.ID)
			if id, ok := b.add(arn, "ec2", "ec2:vpc", r, map[string]any{
				"name": v.Name, "state": v.State, "tag_count": v.TagCount}); ok {
				vpcARN[r+"/"+v.ID] = id
			}
		}
		return err
	})
	sgs := map[string]string{}
	var regionGroups = map[string][]SecurityGroup{}
	each("security-groups", func(ctx context.Context, r string) error {
		gs, err := c.client.SecurityGroups(ctx, r)
		for _, g := range gs {
			arn := fmt.Sprintf("arn:%s:ec2:%s:%s:security-group/%s", partition(r), r, acct, g.ID)
			regionGroups[r] = append(regionGroups[r], g)
			attrs := map[string]any{"name": g.Name, "tag_count": g.TagCount}
			if g.OpenToInternet {
				attrs["internet_exposed"] = "true"
			}
			if id, ok := b.add(arn, "ec2", "ec2:security-group", r, attrs); ok {
				sgs[r+"/"+g.ID] = id
			}
		}
		return err
	})
	each("ec2", func(ctx context.Context, r string) error {
		is, err := c.client.Instances(ctx, r)
		for _, i := range is {
			arn := fmt.Sprintf("arn:%s:ec2:%s:%s:instance/%s", partition(r), r, acct, i.ID)
			iattrs := map[string]any{
				"name": i.Name, "state": i.State, "instance_type": i.Type,
				"created_at": ts(i.LaunchTime), "tag_count": i.TagCount}
			if exposed(i, regionGroups[r]) {
				iattrs["internet_exposed"] = "true"
			}
			id, ok := b.add(arn, "ec2", "ec2:instance", r, iattrs)
			if !ok {
				continue
			}
			if v, ok := vpcARN[r+"/"+i.VPCID]; ok {
				b.b.Relations = append(b.b.Relations, batch.Relation{Type: "runs_on", From: id, To: v})
			}
			for _, g := range i.SecurityGroupIDs {
				if sg, ok := sgs[r+"/"+g]; ok {
					b.b.Relations = append(b.b.Relations, batch.Relation{Type: "attached_to", From: id, To: sg})
				}
			}
		}
		return err
	})
	once("s3", func(ctx context.Context) error {
		bs, err := c.client.Buckets(ctx)
		for _, k := range bs {
			if !selected[k.Region] {
				continue
			}
			b.add("arn:"+partition(k.Region)+":s3:::"+k.Name, "s3", "s3:bucket", k.Region,
				map[string]any{"name": k.Name, "created_at": ts(k.CreatedAt)})
		}
		return err
	})
	once("iam", func(ctx context.Context) error {
		rs, err := c.client.Roles(ctx)
		for _, r := range rs {
			b.add(r.ARN, "iam", "iam:role", "", map[string]any{"name": r.Name, "created_at": ts(r.CreatedAt)})
		}
		return err
	})
	each("lambda", func(ctx context.Context, r string) error {
		fs, err := c.client.Functions(ctx, r)
		for _, f := range fs {
			b.add(f.ARN, "lambda", "lambda:function", r, map[string]any{"name": f.Name, "runtime": f.Runtime})
		}
		return err
	})
	each("rds", func(ctx context.Context, r string) error {
		ds, err := c.client.DBInstances(ctx, r)
		for _, d := range ds {
			b.add(d.ARN, "rds", "rds:instance", r, map[string]any{
				"name": d.ID, "engine": d.Engine, "state": d.Status, "created_at": ts(d.CreatedAt)})
		}
		return err
	})

	if rejectedErr != nil {
		return graph.Batch{}, c.rejected(rejectedErr)
	}
	if len(failed) == attempted {
		// Nothing usable: an empty full observation would delete every entity.
		return graph.Batch{}, errors.New("aws: every resource type failed")
	}
	if len(failed) > 0 {
		types := make([]string, 0, len(failed))
		for t := range failed {
			types = append(types, t)
		}
		sort.Strings(types)
		return b.b, collectors.PartialError{Types: types}
	}
	return b.b, nil
}

func (c *collector) waitObserver(scope string) func(broker.RateWait) {
	return func(w broker.RateWait) { c.status.Wait(scope, w.Until, w.Waited) }
}

func isRejected(err error) bool {
	return errors.Is(err, ErrExpired) || errors.Is(err, ErrInvalidCredential)
}

// rejected records the authorization error and tags err so the supervisor
// sets the connection EXPIRED.
func (c *collector) rejected(err error) error {
	c.status.Auth("provider rejected the credentials")
	return fmt.Errorf("%w: %w", &lifecycle.HTTPStatusError{Code: lifecycle.StatusUnauthorized}, err)
}
