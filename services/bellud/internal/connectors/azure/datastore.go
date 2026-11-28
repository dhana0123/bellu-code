package azure

import (
	"context"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/azure/azureschema"
)

// StorageAccountsAPIVersion serves the storage account list.
const StorageAccountsAPIVersion = "2023-01-01"

// Data store attribute values. unknown means the data was not readable, never
// that the setting is good.
const (
	stateEnabled  = "enabled"
	stateDisabled = "disabled"
	stateUnknown  = "unknown"
)

type armStorageAccount struct {
	ID         string `json:"id"`
	Properties struct {
		SupportsHTTPSOnly *bool `json:"supportsHttpsTrafficOnly"`
		AllowBlobPublic   *bool `json:"allowBlobPublicAccess"`
		Encryption        struct {
			Services struct {
				Blob struct {
					Enabled *bool `json:"enabled"`
				} `json:"blob"`
			} `json:"services"`
		} `json:"encryption"`
	} `json:"properties"`
}

func triState(v *bool) string {
	switch {
	case v == nil:
		return stateUnknown
	case *v:
		return stateEnabled
	}
	return stateDisabled
}

// dataStoreAttrs returns the five data store attributes, all unknown. The
// generic /resources list carries no properties, so a type with no detail
// read stays unknown. Backup and logging live on child resources that are
// not read.
func dataStoreAttrs() map[string]any {
	return map[string]any{"encryption_at_rest": stateUnknown, "encryption_in_transit": stateUnknown,
		"public_access": stateUnknown, "backup": stateUnknown, "logging": stateUnknown}
}

// storageAttrs maps a storage account's properties to the data store attributes.
func storageAttrs(s armStorageAccount) map[string]any {
	a := dataStoreAttrs()
	a["encryption_at_rest"] = triState(s.Properties.Encryption.Services.Blob.Enabled)
	a["encryption_in_transit"] = triState(s.Properties.SupportsHTTPSOnly)
	if s.Properties.AllowBlobPublic != nil {
		a["public_access"] = triState(s.Properties.AllowBlobPublic)
	}
	return a
}

// storageAccounts reads the storage accounts of one subscription by lower-cased
// id. A failed read is a missing_data gap; the attributes stay unknown.
func (c *collector) storageAccounts(ctx context.Context, sub string) map[string]armStorageAccount {
	out := map[string]armStorageAccount{}
	accts, err := list[armStorageAccount](ctx, c, sub,
		armURL("/subscriptions/"+sub+"/providers/Microsoft.Storage/storageAccounts", StorageAccountsAPIVersion))
	if err != nil {
		c.status.Deny("missing_data:storage-accounts@" + sub)
		return out
	}
	for _, s := range accts {
		out[strings.ToLower(s.ID)] = s
	}
	return out
}

// dataAttrsFor returns the data store attributes of a resource of type t, or nil.
func (c *collector) dataAttrsFor(t, id string, storage func() map[string]armStorageAccount) map[string]any {
	switch t {
	case azureschema.TypeStorageAccount:
		if s, ok := storage()[strings.ToLower(id)]; ok {
			return storageAttrs(s)
		}
		return dataStoreAttrs()
	case azureschema.TypeSQLDatabase:
		return dataStoreAttrs()
	}
	return nil
}
