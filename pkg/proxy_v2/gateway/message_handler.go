package gateway

import (
	"fmt"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common"
)

// readNextMessage 读取下一条消息，完全使用二进制格式
func (c *ClientConn) readNextMessage() (map[string]interface{}, error) {
	// 读取原始消息数据
	msgData, err := c.Conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	// 检查是否是二进制协议消息
	if !common.IsBinaryMessage(msgData) {
		return nil, fmt.Errorf("received non-binary message")
	}

	return c.parseBinaryMessage(msgData)
}

// parseBinaryMessage 解析二进制消息为兼容的 map 格式
func (c *ClientConn) parseBinaryMessage(msgData []byte) (map[string]interface{}, error) {
	version, msgType, data, err := common.UnpackBinaryHeader(msgData)
	if err != nil {
		return nil, err
	}

	_ = version // 暂时不使用版本号

	switch msgType {
	case common.BinaryMsgTypeData:
		// 数据消息
		connID, payload, err := common.UnpackDataMessage(data)
		if err != nil {
			return nil, err
		}

		// 更新接收字节数
		common.AddBytesReceived(int64(len(payload)))

		return map[string]interface{}{
			"type":       common.MsgTypeData,
			"id":         connID,
			"data":       payload, // 直接使用原始数据
			"_optimized": true,
		}, nil

	case common.BinaryMsgTypeConnectResponse:
		// 连接响应
		connID, success, errorMsg, err := common.UnpackConnectResponseMessage(data)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"type":    common.MsgTypeConnectResponse,
			"id":      connID,
			"success": success,
			"error":   errorMsg,
		}, nil

	case common.BinaryMsgTypeClose:
		// 关闭消息
		connID, err := common.UnpackCloseMessage(data)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"type": common.MsgTypeClose,
			"id":   connID,
		}, nil

	case common.BinaryMsgTypePortForward:
		// 端口转发请求
		clientID, ports, err := common.UnpackPortForwardMessage(data)
		if err != nil {
			return nil, err
		}

		// 转换为兼容格式
		openPorts := make([]interface{}, len(ports))
		for i, port := range ports {
			openPorts[i] = map[string]interface{}{
				"remote_port": port.RemotePort,
				"local_port":  port.LocalPort,
				"local_host":  port.LocalHost,
				"protocol":    port.Protocol,
			}
		}

		return map[string]interface{}{
			"type":       common.MsgTypePortForwardReq,
			"client_id":  clientID,
			"open_ports": openPorts,
		}, nil

	default:
		return nil, fmt.Errorf("unknown binary message type: 0x%02x", msgType)
	}
}

// writeDataMessage 发送数据消息，使用二进制格式
func (c *ClientConn) writeDataMessage(connID string, data []byte) error {
	// 使用二进制格式
	binaryMsg := common.PackDataMessage(connID, data)

	// 更新发送的字节数
	common.AddBytesSent(int64(len(data)))

	return c.Conn.WriteMessage(binaryMsg)
}

// writeConnectMessage 发送连接请求，使用二进制格式
func (c *ClientConn) writeConnectMessage(connID, network, address string) error {
	// 使用二进制格式
	binaryMsg := common.PackConnectMessage(connID, network, address)

	return c.Conn.WriteMessage(binaryMsg)
}

// writeCloseMessage 发送关闭消息，使用二进制格式
func (c *ClientConn) writeCloseMessage(connID string) error {
	// 使用二进制格式
	binaryMsg := common.PackCloseMessage(connID)

	return c.Conn.WriteMessage(binaryMsg)
}
