package proxy_protocols // nolint:revive // Package name intentionally uses underscore to avoid conflict with main proxy package

import "strings"

// extractBaseUsername extracts the base username (same as v1)
func extractBaseUsername(username string) string {
	parts := strings.Split(username, ".")
	if len(parts) >= 1 {
		return parts[0]
	}
	return username
}
