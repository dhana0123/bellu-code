package aws

import "context"

// noNetwork gives a test Client empty answers for every network and load
// balancer listing. Fakes embed it and override what they exercise. When rec
// is set, every call is passed to it with the step name and region, and its
// error is returned.
type noNetwork struct {
	rec func(op, region string) error
}

func (n noNetwork) call(op, region string) error {
	if n.rec == nil {
		return nil
	}
	return n.rec(op, region)
}

func (n noNetwork) Subnets(_ context.Context, r string) (Listing[Subnet], error) {
	return Listing[Subnet]{}, n.call("subnet", r)
}
func (n noNetwork) ENIs(_ context.Context, r string) (Listing[ENI], error) {
	return Listing[ENI]{}, n.call("eni", r)
}
func (n noNetwork) RouteTables(_ context.Context, r string) (Listing[RouteTable], error) {
	return Listing[RouteTable]{}, n.call("route-table", r)
}
func (n noNetwork) InternetGateways(_ context.Context, r string) (Listing[InternetGateway], error) {
	return Listing[InternetGateway]{}, n.call("igw", r)
}
func (n noNetwork) NATGateways(_ context.Context, r string) (Listing[NATGateway], error) {
	return Listing[NATGateway]{}, n.call("nat", r)
}
func (n noNetwork) SGRules(_ context.Context, r string) (Listing[SGRule], error) {
	return Listing[SGRule]{}, n.call("sg-rules", r)
}
func (n noNetwork) NetworkACLs(_ context.Context, r string) (Listing[NetworkACL], error) {
	return Listing[NetworkACL]{}, n.call("nacl", r)
}
func (n noNetwork) VPCEndpoints(_ context.Context, r string) (Listing[VPCEndpoint], error) {
	return Listing[VPCEndpoint]{}, n.call("vpc-endpoint", r)
}
func (n noNetwork) PeeringConnections(_ context.Context, r string) (Listing[PeeringConnection], error) {
	return Listing[PeeringConnection]{}, n.call("peering", r)
}
func (n noNetwork) ElasticIPs(_ context.Context, r string) (Listing[ElasticIP], error) {
	return Listing[ElasticIP]{}, n.call("eip", r)
}
func (n noNetwork) TransitGateways(_ context.Context, r string) (Listing[TransitGateway], error) {
	return Listing[TransitGateway]{}, n.call("tgw", r)
}
func (n noNetwork) TGWAttachments(_ context.Context, r string) (Listing[TGWAttachment], error) {
	return Listing[TGWAttachment]{}, n.call("tgw-attachment", r)
}
func (n noNetwork) LoadBalancers(_ context.Context, r string) (Listing[LoadBalancer], error) {
	return Listing[LoadBalancer]{}, n.call("lb", r)
}
func (n noNetwork) TargetGroups(_ context.Context, r string) (Listing[TargetGroup], error) {
	return Listing[TargetGroup]{}, n.call("target-group", r)
}
func (n noNetwork) Listeners(_ context.Context, r, _ string) ([]Listener, error) {
	return nil, n.call("listener", r)
}
func (n noNetwork) TargetHealth(_ context.Context, r, _ string) ([]TargetHealth, error) {
	return nil, n.call("target-health", r)
}
