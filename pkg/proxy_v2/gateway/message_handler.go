package gateway

// readNextMessage 读取下一条消息，完全使用二进制格式
func (c *ClientConn) readNextMessage() (map[string]interface{}, error) {
	// 使用公共消息处理器
	return c.msgHandler.ReadNextMessage()
}

// parseBinaryMessage 解析二进制消息为兼容的 map 格式
func (c *ClientConn) parseBinaryMessage(msgData []byte) (map[string]interface{}, error) {
	// 使用公共消息处理器
	return c.msgHandler.ParseBinaryMessage(msgData)
}

// writeDataMessage 发送数据消息，使用二进制格式
func (c *ClientConn) writeDataMessage(connID string, data []byte) error {
	// 使用公共消息处理器
	return c.msgHandler.WriteDataMessage(connID, data)
}

// writeConnectMessage 发送连接请求，使用二进制格式
func (c *ClientConn) writeConnectMessage(connID, network, address string) error {
	// 使用公共消息处理器
	return c.msgHandler.WriteConnectMessage(connID, network, address)
}

// writeCloseMessage 发送关闭消息，使用二进制格式
func (c *ClientConn) writeCloseMessage(connID string) error {
	// 使用公共消息处理器
	return c.msgHandler.WriteCloseMessage(connID)
}
