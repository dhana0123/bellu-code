package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
)

func TestHandlerExposesPrefixedMetrics(t *testing.T) {
	s := New()
	s.BatchApplied("c")
	s.BatchRejected("validation")
	s.EventsAppended("entity_upserted", 2)
	s.Query("get", time.Millisecond)
	s.ObserveApply(time.Millisecond)
	s.ObserveSnapshot(time.Millisecond)
	s.SetEntities(1)
	s.SetRelations(1)
	s.SetLastSequence(5)
	s.SetSubscribers(1)
	s.SubscriberOverflow()
	s.RetentionDeleted(3)
	s.OTLPRecords(1, 1)
	s.SetLocalIDs(2)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	var p expfmt.TextParser
	fams, err := p.TextToMetricFamilies(strings.NewReader(rec.Body.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(fams) != 15 {
		t.Fatalf("want 15 families, got %d", len(fams))
	}
	for name := range fams {
		if !strings.HasPrefix(name, "bellu_graph_") {
			t.Errorf("bad name %s", name)
		}
	}
}
