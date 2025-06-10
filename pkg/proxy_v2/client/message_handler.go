package client

// readNextMessage reads the next message, using binary format completely
func (c *Client) readNextMessage() (map[string]interface{}, error) {
	// Use shared message handler
	return c.msgHandler.ReadNextMessage()
}

// writeDataMessage sends data message using binary format
func (c *Client) writeDataMessage(connID string, data []byte) error {
	// Use shared message handler
	return c.msgHandler.WriteDataMessage(connID, data)
}

// writeConnectResponse sends connection response using binary format
func (c *Client) writeConnectResponse(connID string, success bool, errorMsg string) error {
	// Use shared message handler
	return c.msgHandler.WriteConnectResponse(connID, success, errorMsg)
}

// writeCloseMessage sends close message using binary format
func (c *Client) writeCloseMessage(connID string) error {
	// Use shared message handler
	return c.msgHandler.WriteCloseMessage(connID)
}
