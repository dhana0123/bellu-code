package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws/awsschema"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// step is one unit of collection. Steps run in the order of collectSteps.
type step struct {
	name   string
	types  []string // resource_type values the step emits
	kinds  []string // other kinds the step emits (rule nodes, cidr nodes)
	global bool     // runs once, not once per region
	deps   []string // steps whose failure in a region means this step cannot observe it
	run    func(r *run, ctx context.Context, region string) error
}

// run is the state of one Collect call.
type run struct {
	c    *collector
	b    *builder
	acct string

	failed    map[string]bool // step -> failed in at least one scope
	failedAt  map[string]bool // step@region ("" for global steps)
	truncated map[string]bool // step@region
	rejected  error           // first credential rejection; ends the run
	retain    []batch.Retain

	selected map[string]bool

	// Collected facts, by region, for relations and exposure.
	vpcs            map[string][]VPC
	subnets         map[string][]Subnet
	enis            map[string]map[string]ENI
	sgs             map[string]map[string]SecurityGroup
	sgRules         map[string]map[string][]SGRule // region -> group id -> rules
	routeTbls       map[string][]RouteTable
	igws            map[string][]InternetGateway
	nacls           map[string][]NetworkACL
	nats            map[string][]NATGateway
	eips            map[string][]ElasticIP
	instances       map[string][]Instance
	lbs             map[string][]LoadBalancer
	targetGrps      map[string][]TargetGroup
	ruleNodes       int             // rule nodes emitted so far
	truncatedGroups map[string]bool // sg ARNs whose rule list was cut
}

// collectSteps lists the steps in dependency order: an entity that another
// step relates to is collected first where possible. Relations are resolved
// after every step, so the order only matters for the facts exposure reads.
var collectSteps = []step{
	{name: "vpc", types: []string{awsschema.TypeVPC}, run: (*run).vpc},
	{name: "subnet", types: []string{awsschema.TypeSubnet}, run: (*run).subnet},
	{name: "security-groups", types: []string{awsschema.TypeSecurityGroup}, run: (*run).securityGroups},
	{name: "sg-rules", kinds: []string{kindSGRule}, run: (*run).sgRulesStep},
	{name: "eni", types: []string{awsschema.TypeENI}, run: (*run).eni},
	{name: "route-table", types: []string{awsschema.TypeRouteTable, awsschema.TypeRoute}, run: (*run).routeTable},
	{name: "igw", types: []string{awsschema.TypeInternetGateway}, run: (*run).igw},
	{name: "nat", types: []string{awsschema.TypeNATGateway}, run: (*run).nat},
	{name: "nacl", types: []string{awsschema.TypeNetworkACL}, run: (*run).nacl},
	{name: "eip", types: []string{awsschema.TypeEIP}, run: (*run).eip},
	{name: "vpc-endpoint", types: []string{awsschema.TypeVPCEndpoint}, run: (*run).vpcEndpoint},
	{name: "peering", types: []string{awsschema.TypeVPCPeering}, run: (*run).peering},
	{name: "tgw", types: []string{awsschema.TypeTransitGateway}, run: (*run).tgw},
	{name: "tgw-attachment", types: []string{awsschema.TypeTGWAttachment}, run: (*run).tgwAttachment},
	{name: "ec2", types: []string{awsschema.TypeInstance}, run: (*run).ec2},
	{name: "lb", types: []string{awsschema.TypeLoadBalancer}, run: (*run).lb},
	{name: "target-group", types: []string{awsschema.TypeTargetGroup}, run: (*run).targetGroup},
	{name: "listener", types: []string{awsschema.TypeListener}, deps: []string{"lb"}, run: (*run).listener},
	{name: "target-health", types: []string{awsschema.TypeTargetGroup}, deps: []string{"target-group"}, run: (*run).targetHealth},
	{name: "s3", types: []string{awsschema.TypeBucket}, global: true, run: (*run).s3},
	{name: "iam", types: []string{awsschema.TypeRole}, global: true, run: (*run).iam},
	{name: "lambda", types: []string{awsschema.TypeLambda}, run: (*run).lambda},
	{name: "rds", types: []string{awsschema.TypeRDSInstance}, run: (*run).rds},
}

// Collect gathers the full current observation. A failing step is skipped,
// keeps its entities through Batch.Retain, and is reported through
// collectors.PartialError.
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
	acctAttrs := map[string]any{
		"connection": c.connID, "account_id": ident.Account, "source": source,
		"alias": c.alias, "regions": strings.Join(c.regions, ","),
	}
	b := &builder{c: c, source: source, account: string(acctID), acctID: ident.Account,
		seen: map[string]string{}, attrs: map[string]map[string]any{"account": acctAttrs}}
	b.b.Collector = source
	b.b.Entities = append(b.b.Entities, batch.Entity{Type: kindAccount, Identity: acctIdn, Attributes: acctAttrs})
	r := &run{
		c: c, b: b, acct: ident.Account,
		failed: map[string]bool{}, failedAt: map[string]bool{}, truncated: map[string]bool{},
		selected: map[string]bool{},
		enis:     map[string]map[string]ENI{},
		sgs:      map[string]map[string]SecurityGroup{},
		sgRules:  map[string]map[string][]SGRule{},
		vpcs:     map[string][]VPC{}, subnets: map[string][]Subnet{}, routeTbls: map[string][]RouteTable{},
		igws: map[string][]InternetGateway{}, nacls: map[string][]NetworkACL{}, nats: map[string][]NATGateway{},
		eips: map[string][]ElasticIP{}, instances: map[string][]Instance{}, lbs: map[string][]LoadBalancer{},
		targetGrps: map[string][]TargetGroup{}, truncatedGroups: map[string]bool{},
	}
	for _, rg := range c.regions {
		r.selected[rg] = true
	}

	for _, s := range collectSteps {
		r.exec(ctx, s)
	}
	if r.rejected != nil {
		return graph.Batch{}, c.rejected(r.rejected)
	}
	if len(r.failed) == len(collectSteps) {
		// Nothing usable: an empty full observation would delete every entity.
		return graph.Batch{}, errors.New("aws: every resource type failed")
	}
	r.exposure()
	b.resolve()
	r.addRetention()
	if len(r.failed) > 0 {
		types := make([]string, 0, len(r.failed))
		for t := range r.failed {
			types = append(types, t)
		}
		sort.Strings(types)
		return b.b, collectors.PartialError{Types: types}
	}
	return b.b, nil
}

// exec runs one step in every selected region, or once for a global step.
func (r *run) exec(ctx context.Context, s step) {
	scopes := r.c.regions
	if s.global {
		scopes = []string{""}
	}
	for _, rg := range scopes {
		if r.rejected != nil {
			return
		}
		if ctx.Err() != nil {
			r.fail(s, rg, ctx.Err())
			continue
		}
		if r.depFailed(s, rg) {
			r.failed[s.name] = true
			r.failedAt[s.name+"@"+rg] = true
			continue
		}
		scope := rg
		if s.global {
			scope = "global"
		}
		if err := s.run(r, broker.WithWaitObserver(ctx, r.c.waitObserver(scope)), rg); err != nil {
			r.fail(s, rg, err)
		}
	}
}

func (r *run) depFailed(s step, region string) bool {
	for _, d := range s.deps {
		if r.failedAt[d+"@"+region] {
			return true
		}
	}
	return false
}

// fail records a failed step scope, a denied scope, or a credential rejection.
func (r *run) fail(s step, region string, err error) {
	r.failed[s.name] = true
	r.failedAt[s.name+"@"+region] = true
	switch {
	case isRejected(err):
		if r.rejected == nil {
			r.rejected = err
		}
	case errors.Is(err, ErrAccessDenied):
		scope := region
		if scope == "" {
			scope = "global"
		}
		r.c.status.Deny(s.name + "@" + scope)
	}
}

// truncate records that a listing stopped at the cap.
func (r *run) truncate(step, region string, l bool) {
	if !l {
		return
	}
	r.truncated[step+"@"+region] = true
	r.b.attrs[r.accountKey()]["truncated"] = "true"
	r.c.status.Truncate(step, 0)
}

// accountKey is the builder.attrs key of the account entity.
func (r *run) accountKey() string { return "account" }

// addRetention appends one Retain rule per failed, denied, or truncated step
// scope so a full observation does not retire what this run could not see.
func (r *run) addRetention() {
	seen := map[string]bool{}
	add := func(kind string, attrs map[string]string) {
		key := kind + fmt.Sprint(attrs)
		if !seen[key] {
			seen[key] = true
			r.b.b.Retain = append(r.b.b.Retain, batch.Retain{Kind: kind, Attrs: attrs})
		}
	}
	for _, s := range collectSteps {
		scopes := r.c.regions
		if s.global {
			scopes = []string{""}
		}
		for _, rg := range scopes {
			k := s.name + "@" + rg
			if !r.failedAt[k] && !r.truncated[k] {
				continue
			}
			for _, t := range s.types {
				attrs := map[string]string{awsschema.DiscriminatorResourceType: t}
				if rg != "" {
					attrs["region"] = rg
				}
				add(kindResource, attrs)
			}
			for _, kind := range s.kinds {
				add(kind, map[string]string{"region": rg})
			}
			if s.name == "sg-rules" || s.name == "security-groups" || s.name == "ec2" {
				add(kindCIDR, nil)
			}
		}
	}
	// A cut-short rule list of one group keeps that group's rule nodes.
	for sg := range r.truncatedGroups {
		add(kindSGRule, map[string]string{"sg": sg})
	}
}

func (r *run) arn(region, service, res string) string {
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s", partition(region), service, region, r.acct, res)
}

func (r *run) ec2ARN(region, res string) string { return r.arn(region, "ec2", res) }

func (r *run) key(region, id string) string { return region + "/" + id }

func (r *run) add(arn, service, rtype, region string, attrs map[string]any) bool {
	_, ok := r.b.add(arn, service, rtype, region, attrs)
	return ok
}

// subnetKey returns the key of a subnet entity.
func (r *run) subnetARN(region, id string) string { return r.ec2ARN(region, "subnet/"+id) }
func (r *run) vpcARN(region, id string) string    { return r.ec2ARN(region, "vpc/"+id) }
func (r *run) sgARN(region, id string) string     { return r.ec2ARN(region, "security-group/"+id) }
func (r *run) eniARN(region, id string) string    { return r.ec2ARN(region, "network-interface/"+id) }
func (r *run) igwARN(region, id string) string    { return r.ec2ARN(region, "internet-gateway/"+id) }
func (r *run) instARN(region, id string) string   { return r.ec2ARN(region, "instance/"+id) }
