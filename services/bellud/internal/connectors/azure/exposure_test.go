package azure

import (
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/exposure"
)

func TestAzureExposure(t *testing.T) {
	a := Analysis{NICs: []NIC{
		{ID: "vm", PublicIP: true, Rules: []NSGRule{
			{ID: "nsg-deny", Inbound: true, Allow: false, Priority: 100, Source: "Internet", Protocol: "Tcp", Ports: []string{"22"}},
			{ID: "nsg-all", Inbound: true, Allow: true, Priority: 200, Source: "*", Protocol: "Tcp", Ports: []string{"20-30"}},
		}},
		{ID: "priv", Rules: []NSGRule{{ID: "n", Inbound: true, Allow: true, Source: "*", Protocol: "*", Ports: []string{"*"}}}},
		{ID: "bad", PublicIP: true, NetworkErr: true},
	}}
	res, failed := a.Analyze()
	p := res["vm"].Ports
	if res["vm"].Value != exposure.Internet || len(p) != 2 || p[0].To != 21 || p[1].From != 23 {
		t.Fatalf("%+v", res["vm"])
	}
	if res["priv"].Value != exposure.Internal || len(failed) != 1 {
		t.Fatal(res, failed)
	}
}
