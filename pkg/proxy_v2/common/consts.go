package common

import "time"

// Message type constants
const (
	MsgTypeConnect         = "connect"
	MsgTypeConnectResponse = "connect_response"
	MsgTypeData            = "data"
	MsgTypeClose           = "close"
	MsgTypePortForwardReq  = "port_forward_request"
	MsgTypePortForwardResp = "port_forward_response"
)

// Protocol constants
const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

// Scheme constants
const (
	SchemeHTTPS = "https"
	SchemeHTTP  = "http"
)

// Transport type constants
const (
	TransportTypeGRPC      = "grpc"
	TransportTypeWebSocket = "websocket"
	TransportTypeQUIC      = "quic"
	TransportTypeDefault   = TransportTypeWebSocket
)

// 超时配置
var (
	// DefaultConnectTimeout 默认连接超时
	DefaultConnectTimeout = 30 * time.Second

	// DefaultReadTimeout 默认读取超时
	DefaultReadTimeout = 30 * time.Second

	// DefaultWriteTimeout 默认写入超时
	DefaultWriteTimeout = 30 * time.Second

	// DefaultShutdownTimeout 默认关闭超时
	DefaultShutdownTimeout = 3 * time.Second

	// DefaultMessageChannelSize 默认消息通道大小
	DefaultMessageChannelSize = 100

	// DefaultBufferSize 默认缓冲区大小
	DefaultBufferSize = 32 * 1024 // 32KB
)

// SetConnectTimeout 设置连接超时（用于测试或动态配置）
func SetConnectTimeout(timeout time.Duration) {
	DefaultConnectTimeout = timeout
}

// SetReadTimeout 设置读取超时
func SetReadTimeout(timeout time.Duration) {
	DefaultReadTimeout = timeout
}

// SetWriteTimeout 设置写入超时
func SetWriteTimeout(timeout time.Duration) {
	DefaultWriteTimeout = timeout
}
