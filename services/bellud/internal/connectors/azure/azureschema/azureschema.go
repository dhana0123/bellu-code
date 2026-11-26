// Package azureschema declares the kinds, resource types, relations and
// categories that the azure source owns. It imports only the standard library
// and schema. Registration with schemaall is separate.
package azureschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// Kind names.
const (
	KindSubscription   = "azure_subscription"
	KindResource       = "azure_resource"
	KindRoleAssignment = "azure_role_assignment"
)

// Category ids.
const (
	CatOwnership = "azure_ownership"
	CatNetwork   = "azure_network"
	CatCompute   = "azure_compute"
	CatIdentity  = "azure_identity"
	CatData      = "azure_data"
	CatAI        = "azure_ai"
)

// DiscriminatorResourceType is the azure_resource discriminator attribute.
const DiscriminatorResourceType = "azure_type"

// Resource type names.
const (
	TypeResourceGroup   = "azure:resource-group"
	TypeVNet            = "azure:vnet"
	TypeSubnet          = "azure:subnet"
	TypeNSG             = "azure:nsg"
	TypeVM              = "azure:vm"
	TypeAKS             = "azure:aks-cluster"
	TypeLoadBalancer    = "azure:load-balancer"
	TypeFunction        = "azure:function-app"
	TypeStorageAccount  = "azure:storage-account"
	TypeSQLDatabase     = "azure:sql-database"
	TypeKeyVault        = "azure:key-vault"
	TypeManagedIdentity = "azure:managed-identity"
	TypeOpenAIDeploy    = "azure:openai-deployment"
)

const resourceAttrs = " Scalar attributes: azure_type (string, one of the declared types); location (string, an Azure region); subscription_id (string); resource_group (string); truncated (string: true, set only when collection was cut short)."

const dataStoreAttrs = " Attributes: encryption_at_rest, encryption_in_transit, public_access, backup, logging; each enabled, disabled or unknown (unknown: not readable)."

func typ(name, category, desc string) schema.TypeDeclaration {
	return schema.TypeDeclaration{Name: name, Category: category, Description: desc}
}

func ovTyp(name, category, desc string, ov schema.OverviewCategory) schema.TypeDeclaration {
	t := typ(name, category, desc)
	t.Overview = ov
	return t
}

// Declaration returns the azure source declaration.
func Declaration() schema.SourceDeclaration {
	return schema.SourceDeclaration{
		Source: schema.SourceAzure,
		Prefix: "azure_",
		Kinds: []schema.KindDeclaration{
			{
				Name:        KindSubscription,
				Overview:    schema.OvCloud,
				Identity:    []string{"connection", "subscription_id"},
				Description: "An Azure subscription that a connection reads. The id is the provider subscription id, so a rename keeps the entity id.",
			},
			{
				Name:          KindResource,
				Overview:      schema.OvCloud,
				Identity:      []string{"connection", "resource_id"},
				Description:   "An Azure resource identified by its Azure resource ID. The azure_type attribute says which type it is." + resourceAttrs,
				Discriminator: DiscriminatorResourceType,
				Types: []schema.TypeDeclaration{
					typ(TypeResourceGroup, CatOwnership, "An Azure resource group."),
					typ(TypeVNet, CatNetwork, "A virtual network."),
					typ(TypeSubnet, CatNetwork, "A virtual network subnet."),
					typ(TypeNSG, CatNetwork, "A network security group that filters traffic."),
					typ(TypeLoadBalancer, CatNetwork, "An Azure load balancer."),
					typ(TypeVM, CatCompute, "A virtual machine."),
					typ(TypeAKS, CatCompute, "An AKS cluster."),
					typ(TypeFunction, CatCompute, "An Azure Functions app."),
					ovTyp(TypeStorageAccount, CatData, "A storage account."+dataStoreAttrs, schema.OvData),
					ovTyp(TypeSQLDatabase, CatData, "A SQL database."+dataStoreAttrs, schema.OvData),
					ovTyp(TypeKeyVault, CatData, "A Key Vault. Secret values are never collected.", schema.OvSecrets),
					ovTyp(TypeManagedIdentity, CatIdentity, "A managed identity.", schema.OvIdentity),
					ovTyp(TypeOpenAIDeploy, CatAI, "An Azure OpenAI deployment.", schema.OvAI),
				},
			},
			{
				Name:        KindRoleAssignment,
				Overview:    schema.OvIdentity,
				Identity:    []string{"connection", "assignment_id"},
				Description: "An Azure role assignment. assignment_id is its Azure resource ID. Attributes: principal_id (string), role_definition_id (string), scope (string, the Azure resource ID it applies to).",
			},
		},
		Relations: relations(),
		Categories: []schema.CategoryDeclaration{
			{ID: CatOwnership, Name: "Ownership", Status: schema.Implemented},
			{ID: CatNetwork, Name: "Network", Status: schema.Implemented},
			{ID: CatCompute, Name: "Compute", Status: schema.Implemented},
			{ID: CatIdentity, Name: "Identity", Status: schema.Implemented},
			{ID: CatData, Name: "Data", Status: schema.Implemented},
			{ID: CatAI, Name: "AI", Status: schema.Implemented},
		},
	}
}
