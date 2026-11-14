package manifest

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

const deviceMarker = "secretmark"

// deviceManifestGen draws a valid manifest whose first auth method is a valid
// device method: https URLs on hosts in egress, each with a matching POST auth
// operation, a non-empty client id and 0 to 20 scopes.
func deviceManifestGen() *rapid.Generator[Manifest] {
	return rapid.Custom(func(t *rapid.T) Manifest {
		m := manifestGen().Draw(t, "base")
		codeHost := hostGen.Draw(t, "code host")
		tokenHost := hostGen.Draw(t, "token host")
		d := &DeviceSpec{
			DeviceCodeURL: "https://" + codeHost + "/c" + rapid.StringMatching(`[a-z/]{0,10}`).Draw(t, "code path"),
			TokenURL:      "https://" + tokenHost + "/t" + rapid.StringMatching(`[a-z/]{0,10}`).Draw(t, "token path"),
			ClientID:      rapid.StringMatching(`[A-Za-z0-9._-]{1,64}`).Draw(t, "client id"),
			Scopes:        nonNil(rapid.SliceOfN(rapid.StringMatching(`[a-z:_]{1,30}`), 0, MaxDeviceScopes).Draw(t, "scopes")),
		}
		authOp := func(host, path string) Operation {
			return Operation{Name: "POST " + path, Class: ClassAuth, Method: "POST", Query: true, Host: host, Path: path}
		}
		ops := m.Operations
		if len(ops) > MaxOperations-2 {
			ops = ops[:MaxOperations-2]
		}
		egress := m.Egress
		if len(egress) > MaxEgress-2 {
			egress = egress[:MaxEgress-2]
		}
		m.Operations = append(append([]Operation{}, ops...), authOp(codeHost, "/c"+strings.TrimPrefix(d.DeviceCodeURL, "https://"+codeHost+"/c")), authOp(tokenHost, "/t"+strings.TrimPrefix(d.TokenURL, "https://"+tokenHost+"/t")))
		m.Egress = append(append([]string{}, egress...), codeHost, tokenHost)
		for i := range m.AuthMethods {
			m.AuthMethods[i].ID = "m" + string(rune('a'+i))
		}
		m.AuthMethods[0].ID = MethodDevice
		m.AuthMethods[0].Device = d
		return m
	})
}

// Feature: github-app-signin, Property 36: Device manifests are validated
// Validates: Requirements 16.2, 16.3
//
// A valid device manifest is accepted and round trips through Marshal and
// Parse unchanged.
func TestPropertyDeviceManifestAcceptedAndRoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := deviceManifestGen().Draw(t, "manifest")
		if errs := Validate(m); len(errs) != 0 {
			t.Fatalf("valid device manifest rejected: %v", errs)
		}
		data, err := Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("round trip changed the manifest:\n%+v\n%+v", got, m)
		}
		again, err := Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, data) {
			t.Fatal("serialization is not stable")
		}
	})
}

// Feature: github-app-signin, Property 36: Device manifests are validated
// Validates: Requirements 16.2, 16.3
//
// A device method with an empty or non-https URL, an empty client id, a URL
// host outside egress, or more than 20 scopes is rejected with an error that
// names the field and never echoes the offending value.
func TestPropertyDeviceManifestRejectsInvalid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := deviceManifestGen().Draw(t, "manifest")
		d := *m.AuthMethods[0].Device
		const p = "auth_methods[0].device."
		var field string
		switch rapid.IntRange(0, 9).Draw(t, "mutation") {
		case 0:
			d.DeviceCodeURL = ""
			field = "device_code_url"
		case 1:
			d.TokenURL = ""
			field = "token_url"
		case 2:
			d.ClientID = rapid.SampledFrom([]string{"", "   "}).Draw(t, "blank client id")
			field = "client_id"
		case 3:
			d.DeviceCodeURL = "http://" + strings.TrimPrefix(d.DeviceCodeURL, "https://")
			field = "device_code_url"
		case 4:
			d.TokenURL = rapid.SampledFrom([]string{"ftp://", "//", ""}).Draw(t, "scheme") + strings.TrimPrefix(d.TokenURL, "https://")
			field = "token_url"
		case 5:
			d.DeviceCodeURL = "https://" + deviceMarker + ".example.org/c"
			field = "device_code_url"
		case 6:
			d.TokenURL = "https://" + deviceMarker + ".example.org/t"
			field = "token_url"
		case 7:
			n := rapid.IntRange(MaxDeviceScopes+1, 40).Draw(t, "scope count")
			d.Scopes = make([]string, n)
			for i := range d.Scopes {
				d.Scopes[i] = deviceMarker
			}
			field = "scopes"
		case 8:
			d.Scopes = append(append([]string{}, d.Scopes...), "  ")
			if len(d.Scopes) > MaxDeviceScopes {
				t.Skip("scope bound reached")
			}
			field = "scopes[" + itoa(len(d.Scopes)-1) + "]"
		default:
			d.DeviceCodeURL = "https://user:" + deviceMarker + "@" + strings.TrimPrefix(d.DeviceCodeURL, "https://")
			field = "device_code_url"
		}
		m.AuthMethods = append([]AuthMethod{}, m.AuthMethods...)
		m.AuthMethods[0].Device = &d
		errs := Validate(m)
		if !hasField(errs, p+field) {
			t.Fatalf("want field %q in %v", p+field, fields(errs))
		}
		for _, e := range errs {
			if strings.Contains(strings.ToLower(e.Error()), deviceMarker) {
				t.Fatalf("offending value echoed: %v", e)
			}
		}
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
