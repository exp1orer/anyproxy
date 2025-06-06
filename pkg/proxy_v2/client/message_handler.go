package client

import (
	"encoding/json"
	"fmt"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common"
)

// readNextMessage 读取下一条消息，完全使用二进制格式
func (c *Client) readNextMessage() (map[string]interface{}, error) {
	// 读取原始消息数据
	msgData, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	// 检查是否是二进制协议消息
	if common.IsBinaryMessage(msgData) {
		return c.parseBinaryMessage(msgData)
	}

	// 兼容旧的 JSON 格式（可以在未来版本中移除）
	var msg map[string]interface{}
	if err := json.Unmarshal(msgData, &msg); err != nil {
		return nil, fmt.Errorf("invalid message format: %v", err)
	}

	return msg, nil
}

// parseBinaryMessage 解析二进制消息为兼容的 map 格式
func (c *Client) parseBinaryMessage(msgData []byte) (map[string]interface{}, error) {
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

	case common.BinaryMsgTypeConnect:
		// 连接请求
		connID, network, address, err := common.UnpackConnectMessage(data)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"type":    common.MsgTypeConnect,
			"id":      connID,
			"network": network,
			"address": address,
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

	case common.BinaryMsgTypePortForwardResp:
		// 端口转发响应
		success, errorMsg, statuses, err := common.UnpackPortForwardResponseMessage(data)
		if err != nil {
			return nil, err
		}

		// 转换状态列表为兼容格式
		var statusMap = make(map[int]bool)
		for _, status := range statuses {
			statusMap[status.Port] = status.Success
		}

		return map[string]interface{}{
			"type":    "port_forward_response",
			"success": success,
			"error":   errorMsg,
			"ports":   statusMap,
		}, nil

	default:
		return nil, fmt.Errorf("unknown binary message type: 0x%02x", msgType)
	}
}

// writeDataMessage 发送数据消息，使用二进制格式
func (c *Client) writeDataMessage(connID string, data []byte) error {
	// 使用二进制格式
	binaryMsg := common.PackDataMessage(connID, data)

	// 更新发送的字节数
	common.AddBytesSent(int64(len(data)))

	return c.conn.WriteMessage(binaryMsg)
}

// writeConnectResponse 发送连接响应，使用二进制格式
func (c *Client) writeConnectResponse(connID string, success bool, errorMsg string) error {
	// 使用二进制格式
	binaryMsg := common.PackConnectResponseMessage(connID, success, errorMsg)

	return c.conn.WriteMessage(binaryMsg)
}

// writeCloseMessage 发送关闭消息，使用二进制格式
func (c *Client) writeCloseMessage(connID string) error {
	// 使用二进制格式
	binaryMsg := common.PackCloseMessage(connID)

	return c.conn.WriteMessage(binaryMsg)
}

// writePortForwardRequest 发送端口转发请求，使用二进制格式
func (c *Client) writePortForwardRequest(clientID string, ports []int) error {
	// 使用二进制格式
	binaryMsg := common.PackPortForwardMessage(clientID, ports)

	return c.conn.WriteMessage(binaryMsg)
}

// writeJSONMessage 发送 JSON 格式的控制消息（已弃用，保留用于兼容）
func (c *Client) writeJSONMessage(msg map[string]interface{}) error {
	return c.conn.WriteJSON(msg)
}
