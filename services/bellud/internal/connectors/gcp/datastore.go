package gcp

import "strings"

// Data store attribute values. unknown means the list response did not carry
// the setting, never that it is good.
const (
	stateEnabled  = "enabled"
	stateDisabled = "disabled"
	stateUnknown  = "unknown"
)

func obj(o map[string]any, k string) map[string]any {
	m, _ := o[k].(map[string]any)
	return m
}

func flag(o map[string]any, k string) string {
	b, ok := o[k].(bool)
	switch {
	case !ok:
		return stateUnknown
	case b:
		return stateEnabled
	}
	return stateDisabled
}

// bucketAttrs reads the data store attributes from a bucket list item.
// Google encrypts all stored data, so encryption at rest is enabled. Public
// access is disabled only when public access prevention is enforced; IAM
// policies are not read, so otherwise it stays unknown.
func bucketAttrs(o map[string]any) map[string]any {
	a := map[string]any{"location": str(o, "location"),
		"encryption_at_rest": stateEnabled, "encryption_in_transit": stateUnknown,
		"public_access": stateUnknown, "backup": stateDisabled, "logging": stateDisabled}
	if str(obj(o, "iamConfiguration"), "publicAccessPrevention") == "enforced" {
		a["public_access"] = stateDisabled
	}
	if obj(o, "versioning")["enabled"] == true {
		a["backup"] = stateEnabled
	}
	if str(obj(o, "logging"), "logBucket") != "" {
		a["logging"] = stateEnabled
	}
	return a
}

// sqlAttrs reads the data store attributes from a Cloud SQL instance. Public
// access is enabled when the instance has a public IPv4 address and an
// authorized network open to the world.
func sqlAttrs(o map[string]any) map[string]any {
	s := obj(o, "settings")
	ip := obj(s, "ipConfiguration")
	a := map[string]any{"location": str(o, "region"),
		"encryption_at_rest": stateEnabled, "encryption_in_transit": stateUnknown,
		"public_access": stateUnknown, "backup": flag(obj(s, "backupConfiguration"), "enabled"),
		"logging": stateUnknown}
	if _, ok := ip["requireSsl"].(bool); ok {
		a["encryption_in_transit"] = flag(ip, "requireSsl")
	} else if m := str(ip, "sslMode"); m != "" {
		a["encryption_in_transit"] = stateDisabled
		if m != "ALLOW_UNENCRYPTED_AND_ENCRYPTED" {
			a["encryption_in_transit"] = stateEnabled
		}
	}
	if v, ok := ip["ipv4Enabled"].(bool); ok {
		a["public_access"] = stateDisabled
		if v && openNetwork(ip) {
			a["public_access"] = stateEnabled
		}
	}
	if flags, ok := s["databaseFlags"].([]any); ok {
		a["logging"] = stateDisabled
		for _, f := range flags {
			m, _ := f.(map[string]any)
			if n := str(m, "name"); strings.HasPrefix(n, "log_") || strings.Contains(n, "audit") {
				a["logging"] = stateEnabled
			}
		}
	}
	return a
}

func openNetwork(ip map[string]any) bool {
	nets, _ := ip["authorizedNetworks"].([]any)
	for _, n := range nets {
		m, _ := n.(map[string]any)
		if v := str(m, "value"); v == "0.0.0.0/0" || v == "::/0" {
			return true
		}
	}
	return false
}
