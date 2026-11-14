package connectors

import (
	"encoding/json"
	"math"
	"unicode/utf16"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// validator checks one decoded JSON object against a route schema. It records
// the names of failing fields only: it never keeps or echoes a submitted value.
// Record-valued fields (credential, params) are named as a whole, never by
// their entry keys.
type validator struct {
	obj map[string]any
	bad []string
}

func (v *validator) fail(name string) {
	for _, b := range v.bad {
		if b == name {
			return
		}
	}
	v.bad = append(v.bad, name)
}

// utf16Len matches the length Effect's Schema.isMinLength/isMaxLength counts.
func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

// str reads a string field. required fields must be present; min/max bound the
// UTF-16 length (max < 0 means unbounded).
func (v *validator) str(name string, required bool, min, max int) (string, bool) {
	raw, ok := v.obj[name]
	if !ok {
		if required {
			v.fail(name)
		}
		return "", false
	}
	s, isStr := raw.(string)
	if !isStr {
		v.fail(name)
		return "", false
	}
	n := utf16Len(s)
	if n < min || (max >= 0 && n > max) {
		v.fail(name)
		return "", false
	}
	return s, true
}

func (v *validator) integer(name string, min, max int) (int, bool) {
	raw, ok := v.obj[name]
	if !ok {
		return 0, false
	}
	num, isNum := raw.(json.Number)
	if !isNum {
		v.fail(name)
		return 0, false
	}
	f, err := num.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || f < float64(min) || f > float64(max) {
		v.fail(name)
		return 0, false
	}
	return int(f), true
}

func (v *validator) boolean(name string) (bool, bool) {
	raw, ok := v.obj[name]
	if !ok {
		return false, false
	}
	b, isBool := raw.(bool)
	if !isBool {
		v.fail(name)
		return false, false
	}
	return b, true
}

func asStringMap(raw any) (map[string]string, bool) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(m))
	for k, e := range m {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out[k] = s
	}
	return out, true
}

func asStringSlice(raw any) ([]string, bool) {
	a, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(a))
	for _, e := range a {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// strMap reads a Record<string,string> field.
func (v *validator) strMap(name string, required bool) (map[string]string, bool) {
	raw, ok := v.obj[name]
	if !ok {
		if required {
			v.fail(name)
		}
		return nil, false
	}
	m, ok := asStringMap(raw)
	if !ok {
		v.fail(name)
		return nil, false
	}
	return m, true
}

func (v *validator) selection(name string) (store.Selection, bool) {
	raw, ok := v.obj[name]
	if !ok {
		return store.Selection{}, false
	}
	o, isObj := raw.(map[string]any)
	if !isObj {
		v.fail(name)
		return store.Selection{}, false
	}
	// regions, repos and items are each optional; a missing list is empty.
	list := func(key string) ([]string, bool) {
		raw, present := o[key]
		if !present {
			return []string{}, true
		}
		return asStringSlice(raw)
	}
	regions, ok1 := list("regions")
	repos, ok2 := list("repos")
	items, ok3 := list("items")
	if len(items) == 0 {
		items = nil
	}
	if !ok1 || !ok2 || !ok3 {
		v.fail(name)
		return store.Selection{}, false
	}
	return store.Selection{Regions: regions, Repos: repos, Items: items}, true
}

// createInput is the validated body of createConnection.
type createInput struct {
	Alias        string
	ConnectorID  string
	AuthConfigID string
	Method       string
	Params       map[string]string
	Credential   map[string]string
	IntervalSec  int
}

// Bounds shared with packages/schema/src/connectors.ts.
const (
	aliasMax    = 40
	intervalMin = 60
	intervalMax = 86400
	rotationMin = 1
	rotationMax = 365
)

func parseCreate(obj map[string]any) (any, []string) {
	v := &validator{obj: obj}
	var in createInput
	in.Alias, _ = v.str("alias", true, 1, aliasMax)
	in.ConnectorID, _ = v.str("connectorId", true, 1, -1)
	in.AuthConfigID, _ = v.str("authConfigId", false, 0, -1)
	in.Method, _ = v.str("method", true, 1, -1)
	if in.Method == "device" {
		// Device Connections are created only by the device-flow service.
		v.fail("method")
	}
	in.Params, _ = v.strMap("params", false)
	in.Credential, _ = v.strMap("credential", true)
	in.IntervalSec, _ = v.integer("intervalSec", intervalMin, intervalMax)
	if len(v.bad) > 0 {
		return nil, v.bad
	}
	return in, nil
}

// updateInput is the validated body of updateConnection; nil means "unchanged".
type updateInput struct {
	Alias                *string
	IntervalSec          *int
	AllowAgentLiveReads  *bool
	Selection            *store.Selection
	RotationIntervalDays *int
}

func parseUpdate(obj map[string]any) (any, []string) {
	v := &validator{obj: obj}
	var in updateInput
	if s, ok := v.str("alias", false, 1, aliasMax); ok {
		in.Alias = &s
	}
	if n, ok := v.integer("intervalSec", intervalMin, intervalMax); ok {
		in.IntervalSec = &n
	}
	if b, ok := v.boolean("allowAgentLiveReads"); ok {
		in.AllowAgentLiveReads = &b
	}
	if s, ok := v.selection("selection"); ok {
		in.Selection = &s
	}
	if n, ok := v.integer("rotationIntervalDays", rotationMin, rotationMax); ok {
		in.RotationIntervalDays = &n
	}
	if len(v.bad) > 0 {
		return nil, v.bad
	}
	return in, nil
}

// replaceInput is the validated body of reconnect and rotate.
type replaceInput struct{ Credential map[string]string }

func parseReplace(obj map[string]any) (any, []string) {
	v := &validator{obj: obj}
	var in replaceInput
	in.Credential, _ = v.strMap("credential", true)
	if len(v.bad) > 0 {
		return nil, v.bad
	}
	return in, nil
}

// authConfigInput is the validated body of createAuthConfig.
type authConfigInput struct {
	Name     string
	Method   string
	Scopes   []string
	Settings map[string]string
	Secrets  map[string]string
}

const authConfigNameMax = 80

func parseCreateAuthConfig(obj map[string]any) (any, []string) {
	v := &validator{obj: obj}
	var in authConfigInput
	in.Name, _ = v.str("name", true, 1, authConfigNameMax)
	in.Method, _ = v.str("method", true, 1, -1)
	if raw, ok := obj["scopes"]; ok {
		sc, ok := asStringSlice(raw)
		if !ok {
			v.fail("scopes")
		}
		in.Scopes = sc
	}
	in.Settings, _ = v.strMap("settings", false)
	in.Secrets, _ = v.strMap("secrets", false)
	if len(v.bad) > 0 {
		return nil, v.bad
	}
	return in, nil
}

type awsSetupInput struct{ Alias string }

func parseAwsSetup(obj map[string]any) (any, []string) {
	v := &validator{obj: obj}
	var in awsSetupInput
	in.Alias, _ = v.str("alias", false, 1, aliasMax)
	if len(v.bad) > 0 {
		return nil, v.bad
	}
	return in, nil
}

type unlockInput struct{ Passphrase string }

func parseUnlock(obj map[string]any) (any, []string) {
	v := &validator{obj: obj}
	var in unlockInput
	in.Passphrase, _ = v.str("passphrase", true, 1, -1)
	if len(v.bad) > 0 {
		return nil, v.bad
	}
	return in, nil
}

// parseScope validates a ScopeInput; the principal comes from the path.
func parseScope(obj map[string]any) (any, []string) {
	v := &validator{obj: obj}
	var sc store.Scope
	for _, f := range []struct {
		name string
		dst  *[]string
	}{{"connectors", &sc.Connectors}, {"connections", &sc.Connections}} {
		raw, ok := obj[f.name]
		if !ok {
			v.fail(f.name)
			continue
		}
		list, ok := asStringSlice(raw)
		if !ok {
			v.fail(f.name)
			continue
		}
		*f.dst = list
	}
	sc.Operations = map[string][]string{}
	if raw, ok := obj["operations"]; !ok {
		v.fail("operations")
	} else if m, ok := raw.(map[string]any); !ok {
		v.fail("operations")
	} else {
		for k, e := range m {
			list, ok := asStringSlice(e)
			if !ok {
				v.fail("operations")
				break
			}
			sc.Operations[k] = list
		}
	}
	if len(v.bad) > 0 {
		return nil, v.bad
	}
	return sc, nil
}

// startDeviceInput is the validated body of startDeviceAuthorization. The body
// is closed: other fields (client_secret and the like) are ignored.
type startDeviceInput struct{ ConnectorID, Alias, ReconnectID string }

func parseStartDevice(obj map[string]any) (any, []string) {
	v := &validator{obj: obj}
	var in startDeviceInput
	in.ConnectorID, _ = v.str("connectorId", true, 1, -1)
	in.ReconnectID, _ = v.str("reconnectId", false, 1, -1)
	in.Alias, _ = v.str("alias", in.ReconnectID == "", 1, aliasMax)
	if len(v.bad) > 0 {
		return nil, v.bad
	}
	return in, nil
}
