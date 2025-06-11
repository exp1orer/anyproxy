package client

import (
	"fmt"

	"github.com/rs/xid"
)

// getClientID gets client ID for logging use
func (c *Client) getClientID() string {
	if c.actualID != "" {
		return c.actualID
	}
	return c.config.ClientID
}

// generateClientID generates a unique client ID
func (c *Client) generateClientID() string {
	// Fix: Include replica index in generated ID to ensure uniqueness
	generatedID := fmt.Sprintf("%s-r%d-%s", c.config.ClientID, c.replicaIdx, xid.New().String())
	return generatedID
}
