package graph

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/lens"
)

func TestSliceValidatesNewParameters(t *testing.T) {
	h := New(nil, nil, WithLens(lens.NewService()))
	for _, c := range []struct{ query, field string }{
		{"/slice?lens=cloud&collapse_rules=yes", "collapse_rules"},
		{"/slice?lens=attack-path&target_type=nope:thing", "target_type"},
	} {
		code, body := get(t, h, c.query)
		if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(body), c.field) {
			t.Errorf("%s: %d %s", c.query, code, body)
		}
	}
	// Valid values pass validation and reach the (unbound) service.
	code, _ := get(t, h, "/slice?lens=attack-path&target_type=rds:instance&collapse_rules=false")
	if code != http.StatusServiceUnavailable {
		t.Errorf("valid parameters: %d", code)
	}
}
