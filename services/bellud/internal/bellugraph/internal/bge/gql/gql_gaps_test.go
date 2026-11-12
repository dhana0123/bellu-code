package gql

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestQueriesWithAndWithoutAsOf(t *testing.T) {
	f := newFixture(t)
	before := t0.Add(-time.Minute).Format(time.RFC3339Nano)
	at := t0.Format(time.RFC3339Nano)
	host, lp := f.ids["host"], f.ids["lp"]

	for _, tc := range []struct {
		name, query     string
		now, early      string // substrings expected without asOf / before the ingest
		earlyErrCode    string
		withVarsAsOfKey string
	}{
		{"entity", `query($id: ID!, $at: Time) { entity(id: $id, asOf: $at) { kind } }`, `"kind":"host"`, "null", "NOT_FOUND", ""},
		{"find", `query($at: Time) { find(kind: "host", asOf: $at) { total } }`, `"total":1`, `"total":0`, "", ""},
		{"neighbors", `query($id: ID!, $at: Time) { neighbors(id: $id, asOf: $at) { total } }`, `"total":1`, "", "NOT_FOUND", ""},
		{"path", `query($id: ID!, $b: ID!, $at: Time) { path(from: $id, to: $b, asOf: $at) { connected } }`, `"connected":true`, "", "NOT_FOUND", ""},
		{"impact", `query($id: ID!, $at: Time) { impact(id: $id, asOf: $at) { hops } }`, `"hops":1`, "", "NOT_FOUND", ""},
	} {
		id := host
		if tc.name == "path" {
			id = lp
		}
		vars := func(at any) map[string]any {
			m := map[string]any{"id": id, "b": host}
			if at != nil {
				m["at"] = at
			}
			return m
		}
		r := f.do(t, tc.query, vars(nil))
		if len(r.Errors) > 0 || !strings.Contains(string(r.Data[tc.name]), tc.now) {
			t.Errorf("%s now: %s %+v", tc.name, r.Data[tc.name], r.Errors)
		}
		r = f.do(t, tc.query, vars(at))
		if len(r.Errors) > 0 || !strings.Contains(string(r.Data[tc.name]), tc.now) {
			t.Errorf("%s at ingest: %s %+v", tc.name, r.Data[tc.name], r.Errors)
		}
		r = f.do(t, tc.query, vars(before))
		if tc.earlyErrCode != "" {
			if fmt.Sprint(codes(r)) != "["+tc.earlyErrCode+"]" {
				t.Errorf("%s before: codes %v", tc.name, codes(r))
			}
			continue
		}
		if !strings.Contains(string(r.Data[tc.name]), tc.early) {
			t.Errorf("%s before: %s %+v", tc.name, r.Data[tc.name], r.Errors)
		}
	}
}

func TestHistoryAndChangeQueries(t *testing.T) {
	f := newFixture(t)
	r := f.do(t, `query($id: ID!) { history(id: $id) { total items { kind subject } } recentChanges { total } recentDigest { total } diff(from: "2024-01-01T00:00:00Z", to: "2030-01-01T00:00:00Z") { added { id } } }`,
		map[string]any{"id": f.ids["host"]})
	if len(r.Errors) > 0 {
		t.Fatalf("errors: %+v", r.Errors)
	}
	if !strings.Contains(string(r.Data["history"]), `"ADDED"`) || strings.Contains(string(r.Data["recentChanges"]), `"total":0`) ||
		strings.Contains(string(r.Data["recentDigest"]), `"total":0`) || !strings.Contains(string(r.Data["diff"]), f.ids["host"]) {
		t.Fatalf("data: %s", r.Data)
	}
}

func TestComplexityLimit(t *testing.T) {
	f := newFixture(t)
	// Thousands of aliased fields push the cost past MaxComplexity.
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&b, ` a%d: entity(id: "x") { id kind label attributes }`, i)
	}
	b.WriteString("}")
	r := f.do(t, b.String(), nil)
	if len(r.Errors) == 0 || codes(r)[0] != CodeValidation {
		t.Fatalf("complexity: codes %v errors %+v", codes(r), r.Errors)
	}
}

func TestChangesSubscriptionWebsocket(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(f.srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, url, map[string][]string{"Sec-WebSocket-Protocol": {"graphql-transport-ws"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	send := func(m map[string]any) {
		if err := conn.WriteJSON(m); err != nil {
			t.Fatal(err)
		}
	}
	read := func() map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := conn.ReadJSON(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	send(map[string]any{"type": "connection_init"})
	if ty := string(read()["type"]); ty != `"connection_ack"` {
		t.Fatalf("ack = %s", ty)
	}
	send(map[string]any{"id": "1", "type": "subscribe", "payload": map[string]any{
		"query": `subscription { changes(fromSeq: "0", filter: {subject: ENTITY}) { seq kind subject } }`}})
	n := 0
	for n < 2 {
		m := read()
		if string(m["type"]) == `"ping"` {
			continue
		}
		if string(m["type"]) != `"next"` || !strings.Contains(string(m["payload"]), `"kind":"ADDED"`) {
			t.Fatalf("frame = %v", m)
		}
		n++
	}
}
