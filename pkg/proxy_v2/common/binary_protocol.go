package common

import (
	"encoding/binary"
	"fmt"
)

// 二进制协议版本
const (
	BinaryProtocolVersion byte = 1
)

// 二进制消息类型定义
const (
	// 控制消息类型 (0x00 - 0x0F)
	BinaryMsgTypeConnect         byte = 0x01 // 连接请求
	BinaryMsgTypeConnectResponse byte = 0x02 // 连接响应
	BinaryMsgTypeClose           byte = 0x03 // 关闭连接
	BinaryMsgTypePortForward     byte = 0x04 // 端口转发请求
	BinaryMsgTypePortForwardResp byte = 0x05 // 端口转发响应

	// 数据消息类型 (0x10 - 0x1F)
	BinaryMsgTypeData byte = 0x10 // 数据传输

	// 预留类型 (0x20 - 0xFF)
)

// 消息头大小
const (
	BinaryHeaderSize = 2  // [版本:1字节][类型:1字节]
	ConnIDSize       = 20 // xid 字符串长度
)

// BinaryMessage 二进制消息基础结构
type BinaryMessage struct {
	Version byte   // 协议版本
	Type    byte   // 消息类型
	ConnID  string // 连接ID (20字符)
	Data    []byte // 消息数据
}

// PackBinaryMessage 打包任意类型的二进制消息
// 格式: [版本:1][类型:1][数据:N]
// 数据部分根据消息类型有不同的格式
func PackBinaryMessage(msgType byte, data []byte) []byte {
	msg := make([]byte, BinaryHeaderSize+len(data))
	msg[0] = BinaryProtocolVersion
	msg[1] = msgType
	copy(msg[2:], data)
	return msg
}

// UnpackBinaryHeader 解包消息头，返回版本、类型和数据部分
func UnpackBinaryHeader(msg []byte) (version, msgType byte, data []byte, err error) {
	if len(msg) < BinaryHeaderSize {
		return 0, 0, nil, fmt.Errorf("message too short: %d bytes", len(msg))
	}

	version = msg[0]
	msgType = msg[1]
	data = msg[2:]

	if version != BinaryProtocolVersion {
		return 0, 0, nil, fmt.Errorf("unsupported version: %d", version)
	}

	return version, msgType, data, nil
}

// IsBinaryMessage 检查是否是二进制协议消息
func IsBinaryMessage(data []byte) bool {
	if len(data) < BinaryHeaderSize {
		return false
	}
	return data[0] == BinaryProtocolVersion
}

// --- 数据消息 (最高频) ---
// 格式: [版本:1][类型:1][connID:20][数据:N]

// PackDataMessage 打包数据消息
func PackDataMessage(connID string, data []byte) []byte {
	if len(connID) > ConnIDSize {
		connID = connID[:ConnIDSize]
	}

	payload := make([]byte, ConnIDSize+len(data))

	// 复制 connID，不足部分补零
	connIDBytes := []byte(connID)
	copy(payload[:ConnIDSize], connIDBytes)

	// 复制数据
	copy(payload[ConnIDSize:], data)

	return PackBinaryMessage(BinaryMsgTypeData, payload)
}

// UnpackDataMessage 解包数据消息
func UnpackDataMessage(data []byte) (connID string, payload []byte, err error) {
	if len(data) < ConnIDSize {
		return "", nil, fmt.Errorf("data message too short: %d bytes", len(data))
	}

	// 提取 connID (去除尾部零字节)
	connIDBytes := data[:ConnIDSize]
	for i, b := range connIDBytes {
		if b == 0 {
			connID = string(connIDBytes[:i])
			break
		}
	}
	if connID == "" {
		connID = string(connIDBytes)
	}

	payload = data[ConnIDSize:]
	return connID, payload, nil
}

// --- 连接请求消息 ---
// 格式: [版本:1][类型:1][connID:20][network长度:2][network:N][address长度:2][address:N]

// PackConnectMessage 打包连接请求
func PackConnectMessage(connID, network, address string) []byte {
	if len(connID) > ConnIDSize {
		connID = connID[:ConnIDSize]
	}

	networkBytes := []byte(network)
	addressBytes := []byte(address)

	// 计算总长度
	totalLen := ConnIDSize + 2 + len(networkBytes) + 2 + len(addressBytes)
	payload := make([]byte, totalLen)

	offset := 0

	// connID (固定20字节)
	copy(payload[offset:offset+ConnIDSize], []byte(connID))
	offset += ConnIDSize

	// network长度 (2字节)
	binary.BigEndian.PutUint16(payload[offset:], uint16(len(networkBytes)))
	offset += 2

	// network内容
	copy(payload[offset:], networkBytes)
	offset += len(networkBytes)

	// address长度 (2字节)
	binary.BigEndian.PutUint16(payload[offset:], uint16(len(addressBytes)))
	offset += 2

	// address内容
	copy(payload[offset:], addressBytes)

	return PackBinaryMessage(BinaryMsgTypeConnect, payload)
}

// UnpackConnectMessage 解包连接请求
func UnpackConnectMessage(data []byte) (connID, network, address string, err error) {
	if len(data) < ConnIDSize+4 {
		return "", "", "", fmt.Errorf("connect message too short: %d bytes", len(data))
	}

	offset := 0

	// 提取 connID
	connIDBytes := data[offset : offset+ConnIDSize]
	for i, b := range connIDBytes {
		if b == 0 {
			connID = string(connIDBytes[:i])
			break
		}
	}
	if connID == "" {
		connID = string(connIDBytes)
	}
	offset += ConnIDSize

	// 提取 network
	networkLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(networkLen) > len(data) {
		return "", "", "", fmt.Errorf("invalid network length")
	}
	network = string(data[offset : offset+int(networkLen)])
	offset += int(networkLen)

	// 提取 address
	if offset+2 > len(data) {
		return "", "", "", fmt.Errorf("missing address length")
	}
	addressLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(addressLen) > len(data) {
		return "", "", "", fmt.Errorf("invalid address length")
	}
	address = string(data[offset : offset+int(addressLen)])

	return connID, network, address, nil
}

// --- 连接响应消息 ---
// 格式: [版本:1][类型:1][connID:20][success:1][error长度:2][error:N]

// PackConnectResponseMessage 打包连接响应
func PackConnectResponseMessage(connID string, success bool, errorMsg string) []byte {
	if len(connID) > ConnIDSize {
		connID = connID[:ConnIDSize]
	}

	errorBytes := []byte(errorMsg)

	// 计算总长度
	totalLen := ConnIDSize + 1 + 2 + len(errorBytes)
	payload := make([]byte, totalLen)

	offset := 0

	// connID (固定20字节)
	copy(payload[offset:offset+ConnIDSize], []byte(connID))
	offset += ConnIDSize

	// success (1字节)
	if success {
		payload[offset] = 1
	} else {
		payload[offset] = 0
	}
	offset++

	// error长度 (2字节)
	binary.BigEndian.PutUint16(payload[offset:], uint16(len(errorBytes)))
	offset += 2

	// error内容
	copy(payload[offset:], errorBytes)

	return PackBinaryMessage(BinaryMsgTypeConnectResponse, payload)
}

// UnpackConnectResponseMessage 解包连接响应
func UnpackConnectResponseMessage(data []byte) (connID string, success bool, errorMsg string, err error) {
	if len(data) < ConnIDSize+3 {
		return "", false, "", fmt.Errorf("connect response too short: %d bytes", len(data))
	}

	offset := 0

	// 提取 connID
	connIDBytes := data[offset : offset+ConnIDSize]
	for i, b := range connIDBytes {
		if b == 0 {
			connID = string(connIDBytes[:i])
			break
		}
	}
	if connID == "" {
		connID = string(connIDBytes)
	}
	offset += ConnIDSize

	// 提取 success
	success = data[offset] == 1
	offset++

	// 提取 error
	errorLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if errorLen > 0 {
		if offset+int(errorLen) > len(data) {
			return "", false, "", fmt.Errorf("invalid error length")
		}
		errorMsg = string(data[offset : offset+int(errorLen)])
	}

	return connID, success, errorMsg, nil
}

// --- 关闭消息 ---
// 格式: [版本:1][类型:1][connID:20]

// PackCloseMessage 打包关闭消息
func PackCloseMessage(connID string) []byte {
	if len(connID) > ConnIDSize {
		connID = connID[:ConnIDSize]
	}

	payload := make([]byte, ConnIDSize)
	copy(payload, []byte(connID))

	return PackBinaryMessage(BinaryMsgTypeClose, payload)
}

// UnpackCloseMessage 解包关闭消息
func UnpackCloseMessage(data []byte) (connID string, err error) {
	if len(data) < ConnIDSize {
		return "", fmt.Errorf("close message too short: %d bytes", len(data))
	}

	// 提取 connID
	connIDBytes := data[:ConnIDSize]
	for i, b := range connIDBytes {
		if b == 0 {
			connID = string(connIDBytes[:i])
			break
		}
	}
	if connID == "" {
		connID = string(connIDBytes)
	}

	return connID, nil
}

// --- 端口转发请求 ---
// 格式: [版本:1][类型:1][clientID长度:2][clientID:N][端口数量:2][端口1:2][端口2:2]...

// PackPortForwardMessage 打包端口转发请求
func PackPortForwardMessage(clientID string, ports []int) []byte {
	clientIDBytes := []byte(clientID)

	// 计算总长度
	totalLen := 2 + len(clientIDBytes) + 2 + len(ports)*2
	payload := make([]byte, totalLen)

	offset := 0

	// clientID长度 (2字节)
	binary.BigEndian.PutUint16(payload[offset:], uint16(len(clientIDBytes)))
	offset += 2

	// clientID内容
	copy(payload[offset:], clientIDBytes)
	offset += len(clientIDBytes)

	// 端口数量 (2字节)
	binary.BigEndian.PutUint16(payload[offset:], uint16(len(ports)))
	offset += 2

	// 端口列表
	for _, port := range ports {
		binary.BigEndian.PutUint16(payload[offset:], uint16(port))
		offset += 2
	}

	return PackBinaryMessage(BinaryMsgTypePortForward, payload)
}

// UnpackPortForwardMessage 解包端口转发请求
func UnpackPortForwardMessage(data []byte) (clientID string, ports []int, err error) {
	if len(data) < 4 {
		return "", nil, fmt.Errorf("port forward message too short: %d bytes", len(data))
	}

	offset := 0

	// 提取 clientID
	clientIDLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(clientIDLen) > len(data) {
		return "", nil, fmt.Errorf("invalid clientID length")
	}
	clientID = string(data[offset : offset+int(clientIDLen)])
	offset += int(clientIDLen)

	// 提取端口数量
	if offset+2 > len(data) {
		return "", nil, fmt.Errorf("missing port count")
	}
	portCount := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// 提取端口列表
	ports = make([]int, portCount)
	for i := 0; i < int(portCount); i++ {
		if offset+2 > len(data) {
			return "", nil, fmt.Errorf("invalid port data")
		}
		ports[i] = int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
	}

	return clientID, ports, nil
}

// --- 端口转发响应 ---
// 格式: [版本:1][类型:1][success:1][error长度:2][error:N][转发数量:2][端口1:2][状态1:1]...

// PortForwardStatus 端口转发状态
type PortForwardStatus struct {
	Port    int
	Success bool
}

// PackPortForwardResponseMessage 打包端口转发响应
func PackPortForwardResponseMessage(success bool, errorMsg string, statuses []PortForwardStatus) []byte {
	errorBytes := []byte(errorMsg)

	// 计算总长度
	totalLen := 1 + 2 + len(errorBytes) + 2 + len(statuses)*3
	payload := make([]byte, totalLen)

	offset := 0

	// success (1字节)
	if success {
		payload[offset] = 1
	} else {
		payload[offset] = 0
	}
	offset++

	// error长度 (2字节)
	binary.BigEndian.PutUint16(payload[offset:], uint16(len(errorBytes)))
	offset += 2

	// error内容
	copy(payload[offset:], errorBytes)
	offset += len(errorBytes)

	// 转发数量 (2字节)
	binary.BigEndian.PutUint16(payload[offset:], uint16(len(statuses)))
	offset += 2

	// 状态列表
	for _, status := range statuses {
		binary.BigEndian.PutUint16(payload[offset:], uint16(status.Port))
		offset += 2
		if status.Success {
			payload[offset] = 1
		} else {
			payload[offset] = 0
		}
		offset++
	}

	return PackBinaryMessage(BinaryMsgTypePortForwardResp, payload)
}

// UnpackPortForwardResponseMessage 解包端口转发响应
func UnpackPortForwardResponseMessage(data []byte) (success bool, errorMsg string, statuses []PortForwardStatus, err error) {
	if len(data) < 5 {
		return false, "", nil, fmt.Errorf("port forward response too short: %d bytes", len(data))
	}

	offset := 0

	// 提取 success
	success = data[offset] == 1
	offset++

	// 提取 error
	errorLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if errorLen > 0 {
		if offset+int(errorLen) > len(data) {
			return false, "", nil, fmt.Errorf("invalid error length")
		}
		errorMsg = string(data[offset : offset+int(errorLen)])
		offset += int(errorLen)
	}

	// 提取状态数量
	if offset+2 > len(data) {
		return false, "", nil, fmt.Errorf("missing status count")
	}
	statusCount := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// 提取状态列表
	statuses = make([]PortForwardStatus, statusCount)
	for i := 0; i < int(statusCount); i++ {
		if offset+3 > len(data) {
			return false, "", nil, fmt.Errorf("invalid status data")
		}
		statuses[i].Port = int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		statuses[i].Success = data[offset] == 1
		offset++
	}

	return success, errorMsg, statuses, nil
}
