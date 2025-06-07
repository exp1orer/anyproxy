package client

import (
	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common"
)

// sendPortForwardingRequest 发送端口转发请求 (与 v1 相同)
func (c *Client) sendPortForwardingRequest() error {
	if len(c.config.OpenPorts) == 0 {
		return nil
	}

	logger.Debug("Preparing port forwarding request", "client_id", c.getClientID(), "port_count", len(c.config.OpenPorts))

	// 构建端口配置列表
	ports := make([]common.PortConfig, 0, len(c.config.OpenPorts))
	for _, port := range c.config.OpenPorts {
		ports = append(ports, common.PortConfig{
			RemotePort: port.RemotePort,
			LocalPort:  port.LocalPort,
			LocalHost:  port.LocalHost,
			Protocol:   port.Protocol,
		})
	}

	// 使用二进制格式发送端口转发请求
	binaryMsg := common.PackPortForwardMessage(c.getClientID(), ports)
	return c.conn.WriteMessage(binaryMsg)
}

// handlePortForwardResponse 处理端口转发响应 (与 v1 相同)
func (c *Client) handlePortForwardResponse(msg map[string]interface{}) {
	success, ok := msg["success"].(bool)
	if !ok {
		logger.Error("Invalid port forward response - missing success field", "client_id", c.getClientID())
		return
	}

	if success {
		logger.Info("Port forwarding setup successful", "client_id", c.getClientID())
	} else {
		errorMsg, _ := msg["error"].(string)
		logger.Error("Port forwarding setup failed", "client_id", c.getClientID(), "error", errorMsg)
	}

	// 记录具体的端口状态（如果有的话）
	if portStatuses, ok := msg["port_statuses"].([]interface{}); ok {
		for _, status := range portStatuses {
			if statusMap, ok := status.(map[string]interface{}); ok {
				port, _ := statusMap["port"].(float64)
				success, _ := statusMap["success"].(bool)
				if success {
					logger.Debug("  Port forwarding active", "port", int(port))
				} else {
					logger.Error("  Port forwarding failed", "port", int(port))
				}
			}
		}
	}
}
