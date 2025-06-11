// Package protocols provides utility functions for proxy implementations.
package protocols

import "strings"

// extractBaseUsername extracts the base username
func extractBaseUsername(username string) string {
	parts := strings.Split(username, ".")
	if len(parts) >= 1 {
		return parts[0]
	}
	return username
}
