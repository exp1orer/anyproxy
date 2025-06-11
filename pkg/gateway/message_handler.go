package gateway

// readNextMessage reads the next message, using binary format completely
func (c *ClientConn) readNextMessage() (map[string]interface{}, error) {
	// Use shared message handler
	return c.msgHandler.ReadNextMessage()
}

// writeDataMessage sends data message using binary format
func (c *ClientConn) writeDataMessage(connID string, data []byte) error {
	// Use shared message handler
	return c.msgHandler.WriteDataMessage(connID, data)
}

// writeConnectMessage sends connection request using binary format
func (c *ClientConn) writeConnectMessage(connID, network, address string) error {
	// Use shared message handler
	return c.msgHandler.WriteConnectMessage(connID, network, address)
}

// writeCloseMessage sends close message using binary format
func (c *ClientConn) writeCloseMessage(connID string) error {
	// Use shared message handler
	return c.msgHandler.WriteCloseMessage(connID)
}
