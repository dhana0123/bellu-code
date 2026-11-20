package aws

import (
	"context"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws/awsschema"
)

// This file collects ELBv2 load balancers, target groups, listeners, and
// registered targets, using the ARNs the API returns.

func (r *run) lb(ctx context.Context, rg string) error {
	l, err := r.c.client.LoadBalancers(ctx, rg)
	r.truncate("lb", rg, l.Truncated)
	r.lbs[rg] = l.Items
	for _, x := range l.Items {
		r.add(x.ARN, "elasticloadbalancing", awsschema.TypeLoadBalancer, rg, map[string]any{
			"name": x.Name, "scheme": x.Scheme, "lb_type": x.Type})
		// The ENIs of a load balancer carry "ELB <type>/<name>/<id>" as description.
		suffix := lbENISuffix(x.ARN)
		for _, e := range r.enis[rg] {
			if suffix != "" && e.Description == "ELB "+suffix {
				r.b.rel("aws_has_eni", x.ARN, r.eniARN(rg, e.ID), nil)
			}
		}
	}
	return err
}

// lbENISuffix returns "app/<name>/<id>" from a load balancer ARN.
func lbENISuffix(arn string) string {
	_, s, ok := strings.Cut(arn, ":loadbalancer/")
	if !ok {
		return ""
	}
	return s
}

func (r *run) targetGroup(ctx context.Context, rg string) error {
	l, err := r.c.client.TargetGroups(ctx, rg)
	r.truncate("target-group", rg, l.Truncated)
	r.targetGrps[rg] = l.Items
	for _, g := range l.Items {
		r.add(g.ARN, "elasticloadbalancing", awsschema.TypeTargetGroup, rg, map[string]any{
			"name": g.Name, "target_type": g.TargetType})
	}
	return err
}

func (r *run) listener(ctx context.Context, rg string) error {
	var first error
	for _, lb := range r.lbs[rg] {
		ls, err := r.c.client.Listeners(ctx, rg, lb.ARN)
		if err != nil {
			if first == nil {
				first = err
			}
			if isRejected(err) {
				return err
			}
			continue
		}
		for _, x := range ls {
			r.add(x.ARN, "elasticloadbalancing", awsschema.TypeListener, rg, map[string]any{
				"protocol": x.Protocol, "port": x.Port})
			r.b.rel("aws_lb_listener_of", x.ARN, lb.ARN, nil)
			for _, tg := range x.TargetGroupARNs {
				r.b.rel("aws_lb_forwards_to", x.ARN, tg, nil)
			}
		}
	}
	return first
}

func (r *run) targetHealth(ctx context.Context, rg string) error {
	var first error
	for _, g := range r.targetGrps[rg] {
		ts, err := r.c.client.TargetHealth(ctx, rg, g.ARN)
		if err != nil {
			if first == nil {
				first = err
			}
			if isRejected(err) {
				return err
			}
			continue
		}
		for _, t := range ts {
			switch g.TargetType {
			case "instance":
				r.b.rel("aws_targets", g.ARN, r.instARN(rg, t.TargetID), nil)
			case "lambda":
				r.b.rel("aws_targets", g.ARN, t.TargetID, nil)
			case "ip":
				for _, e := range r.enis[rg] {
					if e.PrivateIP != "" && e.PrivateIP == t.TargetID {
						r.b.rel("aws_targets", g.ARN, r.eniARN(rg, e.ID), nil)
					}
				}
			}
		}
	}
	return first
}
