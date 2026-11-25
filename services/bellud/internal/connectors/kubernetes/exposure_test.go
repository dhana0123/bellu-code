package kubernetes

import (
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/exposure"
)

func TestKubernetesExposure(t *testing.T) {
	a := Analysis{
		Services: []Service{
			{ID: "lb", Name: "lb", Namespace: "a", Type: "LoadBalancer", Selector: map[string]string{"app": "x"},
				Ports: []SvcPort{{Port: 80, TargetPort: 8080}, {Port: 443, TargetPort: 8443}}},
			{ID: "ci", Name: "ci", Namespace: "a", Type: "ClusterIP", Ports: []SvcPort{{Port: 80}}},
			{ID: "np", Name: "np", Namespace: "a", Type: "NodePort", Ports: []SvcPort{{Port: 80, NodePort: 30080}}},
			{ID: "bad", Name: "bad", Namespace: "broken", Type: "LoadBalancer", Ports: []SvcPort{{Port: 80}}},
		},
		Policies: []NetPol{{ID: "np1", Namespace: "a", Ingress: true, Selector: map[string]string{"app": "x"},
			Rules: []PolicyRule{{Internet: true, Ports: []PolicyPort{{Port: 8443, Protocol: "TCP"}}}}}},
		Failed: map[string]bool{"broken": true},
	}
	res, failed := a.Analyze()
	lb := res["lb"]
	if lb.Value != exposure.Internet || len(lb.Ports) != 1 || lb.Ports[0].From != 443 || !lb.Valid() {
		t.Fatalf("lb %+v", lb)
	}
	if res["ci"].Value != exposure.Internal || res["np"].Value != exposure.Internal {
		t.Fatalf("%+v", res)
	}
	if len(failed) != 1 || failed[0] != "bad" {
		t.Fatal(failed)
	}
}
