package azureschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

const edgeAttrs = " Edge attributes: evidence, confidence, observed_at."

func rel(name string, d schema.Direction, desc string, from, to []string) schema.RelationDeclaration {
	return schema.RelationDeclaration{Name: name, Direction: d, Confidence: schema.Extracted, Description: desc + edgeAttrs, From: from, To: to}
}

func relations() []schema.RelationDeclaration {
	res := []string{TypeResourceGroup, TypeVNet, TypeSubnet, TypeNSG, TypeVM, TypeAKS, TypeLoadBalancer, TypeFunction,
		TypeStorageAccount, TypeSQLDatabase, TypeKeyVault, TypeManagedIdentity, TypeOpenAIDeploy}
	return []schema.RelationDeclaration{
		rel("azure_in_subscription", schema.Reverse, "The resource group or resource is contained in the subscription; a subscription change impacts it.",
			[]string{TypeResourceGroup, KindResource}, []string{KindSubscription}),
		rel("azure_in_resource_group", schema.Reverse, "The resource is contained in the resource group; a group change impacts it.",
			res, []string{TypeResourceGroup}),
		rel("azure_in_vnet", schema.Reverse, "The subnet is contained in the virtual network.",
			[]string{TypeSubnet}, []string{TypeVNet}),
		rel("azure_in_subnet", schema.Reverse, "The workload depends on its subnet for connectivity.",
			[]string{TypeVM, TypeAKS, TypeLoadBalancer, TypeFunction}, []string{TypeSubnet}),
		rel("azure_nsg_applies_to", schema.Forward, "The security group filters traffic of the subnet or machine; a rule change changes who reaches it.",
			[]string{TypeNSG}, []string{TypeSubnet, TypeVM}),
		rel("azure_load_balances", schema.Forward, "The load balancer sends traffic to the backend, so reach of the balancer extends to it.",
			[]string{TypeLoadBalancer}, []string{TypeVM, TypeAKS}),
		rel("azure_has_identity", schema.Reverse, "The resource depends on its managed identity; identity compromise impacts the resource.",
			[]string{TypeVM, TypeAKS, TypeFunction, TypeSQLDatabase, TypeStorageAccount}, []string{TypeManagedIdentity}),
		rel("azure_assigned_to", schema.Reverse, "The role assignment depends on its principal; compromise of the principal gains the role.",
			[]string{KindRoleAssignment}, []string{TypeManagedIdentity}),
		rel("azure_assignment_scope", schema.Forward, "The role assignment gives its principal access to the scope resource.",
			[]string{KindRoleAssignment}, []string{KindSubscription, TypeResourceGroup, KindResource}),
		rel("azure_deployed_on", schema.Reverse, "The deployment depends on its Azure OpenAI account.",
			[]string{TypeOpenAIDeploy}, []string{KindResource}),
		rel("azure_stores_in", schema.Forward, "The workload reads or writes the data store, so workload compromise reaches the store.",
			[]string{TypeVM, TypeFunction, TypeAKS}, []string{TypeStorageAccount, TypeSQLDatabase, TypeKeyVault}),
	}
}
