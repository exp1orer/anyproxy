package client

// readNextMessage 读取下一条消息，完全使用二进制格式
func (c *Client) readNextMessage() (map[string]interface{}, error) {
	// 使用公共消息处理器
	return c.msgHandler.ReadNextMessage()
}

// parseBinaryMessage 解析二进制消息为兼容的 map 格式
func (c *Client) parseBinaryMessage(msgData []byte) (map[string]interface{}, error) {
	// 使用公共消息处理器
	return c.msgHandler.ParseBinaryMessage(msgData)
}

// writeDataMessage 发送数据消息，使用二进制格式
func (c *Client) writeDataMessage(connID string, data []byte) error {
	// 使用公共消息处理器
	return c.msgHandler.WriteDataMessage(connID, data)
}

// writeConnectResponse 发送连接响应，使用二进制格式
func (c *Client) writeConnectResponse(connID string, success bool, errorMsg string) error {
	// 使用公共消息处理器
	return c.msgHandler.WriteConnectResponse(connID, success, errorMsg)
}

// writeCloseMessage 发送关闭消息，使用二进制格式
func (c *Client) writeCloseMessage(connID string) error {
	// 使用公共消息处理器
	return c.msgHandler.WriteCloseMessage(connID)
}
