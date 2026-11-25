package findings

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"pgregory.net/rapid"
)

// listDefect breaks one parameter of an otherwise valid list request and
// returns the parameter the handler must name.
type listDefect struct {
	name  string
	apply func(t *rapid.T, v url.Values) string
}

var listDefects = []listDefect{
	{"unknown-name", func(t *rapid.T, v url.Values) string {
		k := "zz_" + rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "unknown")
		v.Set(k, rapid.StringMatching(`[a-z0-9]{0,5}`).Draw(t, "unknownValue"))
		return k
	}},
	{"bad-severity", func(t *rapid.T, v url.Values) string {
		v.Add("severity", "bogus-"+rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "sev"))
		return "severity"
	}},
	{"bad-status", func(t *rapid.T, v url.Values) string {
		v.Add("status", "bogus-"+rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "st"))
		return "status"
	}},
	{"empty-asset", func(t *rapid.T, v url.Values) string {
		v.Add("asset", "")
		return "asset"
	}},
	{"bad-limit", func(t *rapid.T, v url.Values) string {
		v.Set("limit", rapid.SampledFrom([]string{"0", "-1", "501", "abc", "1.5", "", " 5", "+5", "1e2"}).Draw(t, "limit"))
		return "limit"
	}},
	{"bad-sort", func(t *rapid.T, v url.Values) string {
		v.Set("sort", rapid.SampledFrom([]string{"bogus", "-bogus", "--severity", "+severity", " severity", "", "title"}).Draw(t, "sort"))
		return "sort"
	}},
	{"repeated-sort", func(t *rapid.T, v url.Values) string {
		v["sort"] = []string{"severity", "-severity"}
		return "sort"
	}},
	{"bad-from", func(t *rapid.T, v url.Values) string {
		v.Set("from", rapid.SampledFrom([]string{"yesterday", "1700000000", "2025-01-01", "12:00"}).Draw(t, "from"))
		return "from"
	}},
	{"malformed-cursor", func(t *rapid.T, v url.Values) string {
		v.Set("cursor", rapid.SampledFrom([]string{"", "x", "abc.def", "!!.!!", "a.b.c"}).Draw(t, "cursor"))
		return "cursor"
	}},
}

// Feature: bellu-wiz-security-platform, Property 34: For any list request, a parameter outside its domain SHALL be rejected with HTTP 400 naming the parameter, run no query and leave data unchanged; for any well-formed filters and repeated values, the result SHALL equal the AND across distinct filters of the OR across repeated values.
// **Validates: Requirements 20.3, 20.4**
func TestPropertyListInvalidRunsNoQuery(t *testing.T) {
	// The real handler runs over a real store whose database is closed: any
	// query it issued would fail with 500, so a 400 shows the store was not touched.
	e := newEnv(t, true)
	e.db.Close()

	rapid.Check(t, func(t *rapid.T) {
		v := url.Values{}
		if rapid.Bool().Draw(t, "hasSeverity") {
			v["severity"] = rapid.SliceOfN(rapid.SampledFrom([]string{"critical", "high", "medium", "low", "info"}), 1, 3).Draw(t, "severities")
		}
		if rapid.Bool().Draw(t, "hasLimit") {
			v.Set("limit", strconv.Itoa(rapid.IntRange(1, 500).Draw(t, "validLimit")))
		}
		defect := rapid.SampledFrom(listDefects).Draw(t, "defect")
		param := defect.apply(t, v)

		w := e.do("GET", Prefix+"?"+v.Encode(), "", true)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s %v: status %d, want 400: %s", defect.name, v, w.Code, w.Body)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["field"] != param || body["code"] != "invalid_request" {
			t.Fatalf("%s %v: body %v, want field %q", defect.name, v, body, param)
		}
	})
}
