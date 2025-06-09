package message

import (
	"fmt"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/monitoring"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/protocol"
)

// MessageConnection 定义消息连接接口，避免循环导入
type MessageConnection interface {
	// 写入消息（二进制数据）
	WriteMessage(data []byte) error
	// 读取消息
	ReadMessage() ([]byte, error)
}

// MessageHandler 定义消息处理器接口
type MessageHandler interface {
	// 读取下一条消息
	ReadNextMessage() (map[string]interface{}, error)
	// 解析二进制消息
	ParseBinaryMessage(msgData []byte) (map[string]interface{}, error)
	// 发送数据消息
	WriteDataMessage(connID string, data []byte) error
	// 发送关闭消息
	WriteCloseMessage(connID string) error
}

// BinaryMessageHandler 二进制消息处理器的通用实现
type BinaryMessageHandler struct {
	conn     MessageConnection
	isClient bool // 用于区分客户端和网关的消息类型
}

// NewClientMessageHandler 创建客户端消息处理器
func NewClientMessageHandler(conn MessageConnection) MessageHandler {
	return &BinaryMessageHandler{
		conn:     conn,
		isClient: true,
	}
}

// NewGatewayMessageHandler 创建网关消息处理器
func NewGatewayMessageHandler(conn MessageConnection) MessageHandler {
	return &BinaryMessageHandler{
		conn:     conn,
		isClient: false,
	}
}

// ReadNextMessage 读取下一条消息，完全使用二进制格式
func (h *BinaryMessageHandler) ReadNextMessage() (map[string]interface{}, error) {
	// 读取原始消息数据
	msgData, err := h.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	// 检查是否是二进制协议消息
	if !protocol.IsBinaryMessage(msgData) {
		return nil, fmt.Errorf("received non-binary message")
	}

	return h.ParseBinaryMessage(msgData)
}

// ParseBinaryMessage 解析二进制消息为兼容的 map 格式
func (h *BinaryMessageHandler) ParseBinaryMessage(msgData []byte) (map[string]interface{}, error) {
	version, msgType, data, err := protocol.UnpackBinaryHeader(msgData)
	if err != nil {
		return nil, err
	}

	_ = version // 暂时不使用版本号

	// 客户端和网关处理不同的消息类型
	if h.isClient {
		return h.parseClientMessage(msgType, data)
	}
	return h.parseGatewayMessage(msgType, data)
}

// parseClientMessage 解析客户端接收的消息
func (h *BinaryMessageHandler) parseClientMessage(msgType byte, data []byte) (map[string]interface{}, error) {
	switch msgType {
	case protocol.BinaryMsgTypeData:
		// 数据消息
		connID, payload, err := protocol.UnpackDataMessage(data)
		if err != nil {
			return nil, err
		}

		// 更新接收字节数
		monitoring.AddBytesReceived(int64(len(payload)))

		return map[string]interface{}{
			"type":       protocol.MsgTypeData,
			"id":         connID,
			"data":       payload, // 直接使用原始数据
			"_optimized": true,
		}, nil

	case protocol.BinaryMsgTypeConnect:
		// 连接请求
		connID, network, address, err := protocol.UnpackConnectMessage(data)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"type":    protocol.MsgTypeConnect,
			"id":      connID,
			"network": network,
			"address": address,
		}, nil

	case protocol.BinaryMsgTypeClose:
		// 关闭消息
		connID, err := protocol.UnpackCloseMessage(data)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"type": protocol.MsgTypeClose,
			"id":   connID,
		}, nil

	case protocol.BinaryMsgTypePortForwardResp:
		// 端口转发响应
		success, errorMsg, statuses, err := protocol.UnpackPortForwardResponseMessage(data)
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
		return nil, fmt.Errorf("unknown binary message type for client: 0x%02x", msgType)
	}
}

// parseGatewayMessage 解析网关接收的消息
func (h *BinaryMessageHandler) parseGatewayMessage(msgType byte, data []byte) (map[string]interface{}, error) {
	switch msgType {
	case protocol.BinaryMsgTypeData:
		// 数据消息
		connID, payload, err := protocol.UnpackDataMessage(data)
		if err != nil {
			return nil, err
		}

		// 更新接收字节数
		monitoring.AddBytesReceived(int64(len(payload)))

		return map[string]interface{}{
			"type":       protocol.MsgTypeData,
			"id":         connID,
			"data":       payload, // 直接使用原始数据
			"_optimized": true,
		}, nil

	case protocol.BinaryMsgTypeConnectResponse:
		// 连接响应
		connID, success, errorMsg, err := protocol.UnpackConnectResponseMessage(data)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"type":    protocol.MsgTypeConnectResponse,
			"id":      connID,
			"success": success,
			"error":   errorMsg,
		}, nil

	case protocol.BinaryMsgTypeClose:
		// 关闭消息
		connID, err := protocol.UnpackCloseMessage(data)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"type": protocol.MsgTypeClose,
			"id":   connID,
		}, nil

	case protocol.BinaryMsgTypePortForward:
		// 端口转发请求
		clientID, ports, err := protocol.UnpackPortForwardMessage(data)
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
			"type":       protocol.MsgTypePortForwardReq,
			"client_id":  clientID,
			"open_ports": openPorts,
		}, nil

	default:
		return nil, fmt.Errorf("unknown binary message type for gateway: 0x%02x", msgType)
	}
}

// WriteDataMessage 发送数据消息，使用二进制格式
func (h *BinaryMessageHandler) WriteDataMessage(connID string, data []byte) error {
	// 使用二进制格式
	binaryMsg := protocol.PackDataMessage(connID, data)

	// 更新发送的字节数
	monitoring.AddBytesSent(int64(len(data)))

	return h.conn.WriteMessage(binaryMsg)
}

// WriteCloseMessage 发送关闭消息，使用二进制格式
func (h *BinaryMessageHandler) WriteCloseMessage(connID string) error {
	// 使用二进制格式
	binaryMsg := protocol.PackCloseMessage(connID)

	return h.conn.WriteMessage(binaryMsg)
}

// ExtendedMessageHandler 扩展的消息处理器接口（用于特定端的额外功能）
type ExtendedMessageHandler interface {
	MessageHandler
	// 客户端特有的方法
	WriteConnectResponse(connID string, success bool, errorMsg string) error
	// 网关特有的方法
	WriteConnectMessage(connID, network, address string) error
}

// ExtendedBinaryMessageHandler 扩展的二进制消息处理器
type ExtendedBinaryMessageHandler struct {
	*BinaryMessageHandler
}

// NewClientExtendedMessageHandler 创建客户端扩展消息处理器
func NewClientExtendedMessageHandler(conn MessageConnection) ExtendedMessageHandler {
	return &ExtendedBinaryMessageHandler{
		BinaryMessageHandler: &BinaryMessageHandler{
			conn:     conn,
			isClient: true,
		},
	}
}

// NewGatewayExtendedMessageHandler 创建网关扩展消息处理器
func NewGatewayExtendedMessageHandler(conn MessageConnection) ExtendedMessageHandler {
	return &ExtendedBinaryMessageHandler{
		BinaryMessageHandler: &BinaryMessageHandler{
			conn:     conn,
			isClient: false,
		},
	}
}

// WriteConnectResponse 发送连接响应，使用二进制格式（客户端使用）
func (h *ExtendedBinaryMessageHandler) WriteConnectResponse(connID string, success bool, errorMsg string) error {
	// 使用二进制格式
	binaryMsg := protocol.PackConnectResponseMessage(connID, success, errorMsg)

	return h.conn.WriteMessage(binaryMsg)
}

// WriteConnectMessage 发送连接请求，使用二进制格式（网关使用）
func (h *ExtendedBinaryMessageHandler) WriteConnectMessage(connID, network, address string) error {
	// 使用二进制格式
	binaryMsg := protocol.PackConnectMessage(connID, network, address)

	return h.conn.WriteMessage(binaryMsg)
}
