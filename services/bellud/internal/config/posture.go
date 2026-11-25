package config

import (
	"strconv"
	"strings"
)

// Posture holds the posture.* configuration keys, read from BELLUCODE_POSTURE_*.
type Posture struct {
	// CustomDir is posture.custom_dir (BELLUCODE_POSTURE_CUSTOM_DIR): a
	// directory of user Rule_Packs. Empty means none (Requirement 10.13).
	CustomDir string
	// AllowedPorts is network.allowed_ports (BELLUCODE_NETWORK_ALLOWED_PORTS,
	// comma separated): ports the open_ingress rule accepts. Default empty.
	AllowedPorts []int
}

// LoadPosture reads the posture.* keys through env.
func LoadPosture(env func(string) (string, bool)) Posture {
	v, _ := env(envName("posture.custom_dir"))
	p := Posture{CustomDir: strings.TrimSpace(v)}
	raw, _ := env(envName("network.allowed_ports"))
	for _, f := range strings.Split(raw, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && n >= 0 && n <= 65535 {
			p.AllowedPorts = append(p.AllowedPorts, n)
		}
	}
	return p
}
