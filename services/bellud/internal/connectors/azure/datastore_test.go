package azure

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestStorageAccountAttrsAndGap(t *testing.T) {
	for _, denied := range []bool{false, true} {
		c := newTestCollector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := strings.ToLower(r.URL.Path)
			id := "/subscriptions/" + sub + "/resourceGroups/RG1/providers/Microsoft.Storage/storageAccounts/sa1"
			switch {
			case p == "/subscriptions":
				w.Write([]byte(`{"value":[{"subscriptionId":"` + sub + `"}]}`))
			case strings.HasSuffix(p, "/resources"):
				w.Write([]byte(`{"value":[{"id":"` + id + `","type":"Microsoft.Storage/storageAccounts"}]}`))
			case strings.HasSuffix(p, "/storageaccounts") && !denied:
				w.Write([]byte(`{"value":[{"id":"` + id + `","properties":{"supportsHttpsTrafficOnly":true,"allowBlobPublicAccess":false,"encryption":{"services":{"blob":{"enabled":true}}}}}]}`))
			case strings.HasSuffix(p, "/storageaccounts"):
				w.WriteHeader(http.StatusForbidden)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		b, _ := c.Collect(context.Background())
		var got map[string]any
		for _, e := range b.Entities {
			if e.Attributes["azure_type"] == "azure:storage-account" {
				got = e.Attributes
			}
		}
		want := map[string]string{"encryption_at_rest": "enabled", "encryption_in_transit": "enabled", "public_access": "disabled", "backup": "unknown", "logging": "unknown"}
		if denied {
			want = map[string]string{"encryption_at_rest": "unknown", "encryption_in_transit": "unknown", "public_access": "unknown", "backup": "unknown", "logging": "unknown"}
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("denied=%v %s = %v, want %s", denied, k, got[k], v)
			}
		}
		hasGap := false
		for _, d := range c.RunStatus().DeniedScopes {
			hasGap = hasGap || strings.HasPrefix(d, "missing_data:storage-accounts")
		}
		if hasGap != denied {
			t.Errorf("denied=%v denied scopes = %+v", denied, c.RunStatus().DeniedScopes)
		}
	}
}
