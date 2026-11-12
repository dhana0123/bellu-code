// Package metrics holds the bellu_graph_* Prometheus collectors on a private registry.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Set owns the registry and all collectors. Labels carry only fixed values.
type Set struct {
	reg *prometheus.Registry

	applied, rejected, events, queries *prometheus.CounterVec
	otlp                               *prometheus.CounterVec
	entities, relations, lastSeq       prometheus.Gauge
	subscribers, localIDs              prometheus.Gauge
	overflows, retention               prometheus.Counter
	applyDur, snapDur                  prometheus.Histogram
	queryDur                           *prometheus.HistogramVec
}

// New builds a Set with every collector registered.
func New() *Set {
	s := &Set{reg: prometheus.NewRegistry()}
	cv := func(name, help string, l ...string) *prometheus.CounterVec {
		c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, l)
		s.reg.MustRegister(c)
		return c
	}
	c := func(name, help string) prometheus.Counter {
		m := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
		s.reg.MustRegister(m)
		return m
	}
	g := func(name, help string) prometheus.Gauge {
		m := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
		s.reg.MustRegister(m)
		return m
	}
	h := func(name, help string) prometheus.Histogram {
		m := prometheus.NewHistogram(prometheus.HistogramOpts{Name: name, Help: help, Buckets: prometheus.DefBuckets})
		s.reg.MustRegister(m)
		return m
	}
	s.applied = cv("bellu_graph_batches_applied_total", "Batches applied.", "collector")
	s.rejected = cv("bellu_graph_batches_rejected_total", "Batches rejected.", "reason")
	s.events = cv("bellu_graph_events_appended_total", "Events appended.", "type")
	s.queries = cv("bellu_graph_queries_total", "Queries served.", "op")
	s.entities = g("bellu_graph_entities", "Entities in the graph.")
	s.relations = g("bellu_graph_relations", "Relations in the graph.")
	s.lastSeq = g("bellu_graph_log_last_sequence", "Last log sequence.")
	s.subscribers = g("bellu_graph_subscribers", "Active subscribers.")
	s.overflows = c("bellu_graph_subscriber_overflows_total", "Subscriber buffer overflows.")
	s.applyDur = h("bellu_graph_apply_duration_seconds", "Apply latency.")
	s.queryDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "bellu_graph_query_duration_seconds", Help: "Query latency.", Buckets: prometheus.DefBuckets}, []string{"op"})
	s.reg.MustRegister(s.queryDur)
	s.snapDur = h("bellu_graph_snapshot_duration_seconds", "Snapshot duration.")
	s.retention = c("bellu_graph_retention_deleted_events_total", "Events deleted by retention.")
	s.otlp = cv("bellu_graph_otlp_records_total", "OTLP log records.", "result")
	s.localIDs = g("bellu_graph_local_ids", "Live Local_IDs.")
	return s
}

// Handler serves the Prometheus text format.
func (s *Set) Handler() http.Handler {
	return promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{})
}

// Registry returns the private registry.
func (s *Set) Registry() *prometheus.Registry { return s.reg }

// BatchApplied counts an applied batch for a collector.
func (s *Set) BatchApplied(collector string) { s.applied.WithLabelValues(collector).Inc() }

// BatchRejected counts a rejected batch; reason is validation, store or unavailable.
func (s *Set) BatchRejected(reason string) { s.rejected.WithLabelValues(reason).Inc() }

// EventsAppended counts n appended events of the given type.
func (s *Set) EventsAppended(eventType string, n int) {
	s.events.WithLabelValues(eventType).Add(float64(n))
}

// Query counts a served query and observes its latency.
func (s *Set) Query(op string, d time.Duration) {
	s.queries.WithLabelValues(op).Inc()
	s.queryDur.WithLabelValues(op).Observe(d.Seconds())
}

// ObserveApply records Apply latency.
func (s *Set) ObserveApply(d time.Duration) { s.applyDur.Observe(d.Seconds()) }

// ObserveSnapshot records snapshot duration.
func (s *Set) ObserveSnapshot(d time.Duration) { s.snapDur.Observe(d.Seconds()) }

// SetEntities sets the entity gauge.
func (s *Set) SetEntities(n int) { s.entities.Set(float64(n)) }

// SetRelations sets the relation gauge.
func (s *Set) SetRelations(n int) { s.relations.Set(float64(n)) }

// SetLastSequence sets the last log sequence gauge.
func (s *Set) SetLastSequence(seq uint64) { s.lastSeq.Set(float64(seq)) }

// SetSubscribers sets the subscriber gauge.
func (s *Set) SetSubscribers(n int) { s.subscribers.Set(float64(n)) }

// SubscriberOverflow counts a subscriber overflow.
func (s *Set) SubscriberOverflow() { s.overflows.Inc() }

// RetentionDeleted counts n events deleted by retention.
func (s *Set) RetentionDeleted(n int) { s.retention.Add(float64(n)) }

// OTLPRecords counts OTLP records as accepted or rejected.
func (s *Set) OTLPRecords(accepted, rejected int) {
	s.otlp.WithLabelValues("accepted").Add(float64(accepted))
	s.otlp.WithLabelValues("rejected").Add(float64(rejected))
}

// SetLocalIDs sets the live Local_ID gauge.
func (s *Set) SetLocalIDs(n int) { s.localIDs.Set(float64(n)) }
