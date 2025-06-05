package proxy_protocols

import "strings"

// extractBaseUsername extracts the base username (same as v1)
func extractBaseUsername(username string) string {
	parts := strings.Split(username, ".")
	if len(parts) >= 1 {
		return parts[0]
	}
	return username
}
