package github

import (
	"net/url"
	"strings"
)

// ClientID is the public Client_ID of the "Bellu Code" GitHub App. It is not a
// secret and is safe to ship in source. Forks that register their own App set
// BELLUCODE_GITHUB_CLIENT_ID; empty means GitHub sign-in is unavailable.
const ClientID = "Iv23libvjZd1nLPorMij"

// AppSlug is the App's URL slug, used only to build the installation link.
const AppSlug = "bellucode"

// Environment overrides for forks that register their own App.
const (
	EnvClientID = "BELLUCODE_GITHUB_CLIENT_ID"
	EnvAppSlug  = "BELLUCODE_GITHUB_APP_SLUG"
)

// EffectiveClientID returns the trimmed, non-empty environment override, else
// the compiled ClientID.
func EffectiveClientID(getenv func(string) string) string {
	if v := strings.TrimSpace(getenv(EnvClientID)); v != "" {
		return v
	}
	return ClientID
}

// EffectiveAppSlug returns the trimmed, non-empty environment override, else
// the compiled AppSlug.
func EffectiveAppSlug(getenv func(string) string) string {
	if v := strings.TrimSpace(getenv(EnvAppSlug)); v != "" {
		return v
	}
	return AppSlug
}

// InstallURL is the page where the user installs the App.
func InstallURL(slug string) string {
	return "https://github.com/apps/" + url.PathEscape(slug) + "/installations/new"
}
