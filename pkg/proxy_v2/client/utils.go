package client

import (
	"fmt"

	"github.com/rs/xid"
)

// getClientID 获取日志使用的客户端 ID
func (c *Client) getClientID() string {
	if c.actualID != "" {
		return c.actualID
	}
	return c.config.ClientID
}

// generateClientID generates a unique client ID (与 v1 相同)
func (c *Client) generateClientID() string {
	// 修复：在生成的 ID 中包含副本索引，确保唯一性
	generatedID := fmt.Sprintf("%s-r%d-%s", c.config.ClientID, c.replicaIdx, xid.New().String())
	return generatedID
}

// getMessageFields 获取消息的所有字段名（用于调试）(与 v1 相同)
func getMessageFields(msg map[string]interface{}) []string {
	fields := make([]string, 0, len(msg))
	for key := range msg {
		fields = append(fields, key)
	}
	return fields
}
