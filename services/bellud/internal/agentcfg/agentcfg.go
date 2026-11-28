// Package agentcfg builds the BELLUCODE_CONFIG_CONTENT value handed to the TS child.
package agentcfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	// EnvConfigContent is the compatibility name of the child config variable.
	EnvConfigContent = "BELLUCODE_CONFIG_CONTENT"
	// ServerName is the mcp entry key.
	ServerName = "bellu-graph"
	// MCPPath is the Graph MCP endpoint path.
	MCPPath = "/api/experimental/graph/mcp"
)

// ErrInvalidInbound reports an inbound BELLUCODE_CONFIG_CONTENT that is not a JSON object.
var ErrInvalidInbound = errors.New("BELLUCODE_CONFIG_CONTENT is invalid: must be a JSON object")

// MCPURL returns the endpoint URL for a listen address; wildcard or empty hosts become 127.0.0.1.
func MCPURL(host string, port int) string {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + MCPPath
}

// Build returns the config content for the child. inbound/present describe the
// inherited BELLUCODE_CONFIG_CONTENT. When enabled is false the inbound value is
// returned untouched (and ok reports whether to set it at all). An invalid
// inbound value is an error whenever it is present and the entry must be merged.
func Build(inbound string, present, enabled bool, url, token string) (content string, set bool, err error) {
	if !enabled {
		return inbound, present, nil
	}
	root := map[string]json.RawMessage{}
	if present {
		if err := decodeObject([]byte(inbound), &root); err != nil {
			return "", false, fmt.Errorf("%w: %v", ErrInvalidInbound, err)
		}
	}
	mcp := map[string]json.RawMessage{}
	if raw, ok := root["mcp"]; ok {
		if err := decodeObject(raw, &mcp); err != nil {
			return "", false, fmt.Errorf("%w: \"mcp\" must be an object", ErrInvalidInbound)
		}
	}
	entry, err := json.Marshal(map[string]any{
		"type":    "remote",
		"url":     url,
		"headers": map[string]string{"Authorization": "Bearer " + token},
		"oauth":   false,
	})
	if err != nil {
		return "", false, err
	}
	mcp[ServerName] = entry
	if root["mcp"], err = json.Marshal(mcp); err != nil {
		return "", false, err
	}
	out, err := json.Marshal(root)
	return string(out), true, err
}

// ConnectorsServerName is the mcp entry key of the connector MCP endpoint.
const ConnectorsServerName = "bellu-connectors"

// ConnectorsMCPPath is the connector MCP endpoint path.
const ConnectorsMCPPath = "/api/experimental/connectors/mcp"

// ConnectorsMCPURL returns the connector MCP URL for a listen address.
func ConnectorsMCPURL(host string, port int) string {
	return strings.TrimSuffix(MCPURL(host, port), MCPPath) + ConnectorsMCPPath
}

// AddConnectors merges the bellu-connectors mcp entry (its own bearer header)
// into content, the config produced by Build (set reports whether it exists).
// The header is the connector MCP token only: no provider credential, master
// key or passphrase is ever part of the child config.
func AddConnectors(content string, set bool, url, authorization string) (string, error) {
	root := map[string]json.RawMessage{}
	if set {
		if err := decodeObject([]byte(content), &root); err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidInbound, err)
		}
	}
	mcp := map[string]json.RawMessage{}
	if raw, ok := root["mcp"]; ok {
		if err := decodeObject(raw, &mcp); err != nil {
			return "", fmt.Errorf("%w: \"mcp\" must be an object", ErrInvalidInbound)
		}
	}
	entry, err := json.Marshal(map[string]any{
		"type":    "remote",
		"url":     url,
		"headers": map[string]string{"Authorization": authorization},
		"oauth":   false,
	})
	if err != nil {
		return "", err
	}
	mcp[ConnectorsServerName] = entry
	if root["mcp"], err = json.Marshal(mcp); err != nil {
		return "", err
	}
	out, err := json.Marshal(root)
	return string(out), err
}

// decodeObject requires data to be exactly one JSON object (not null, array or scalar).
func decodeObject(data []byte, v *map[string]json.RawMessage) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return errors.New("not an object")
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*v = m
	return nil
}
