package transport

import (
	"crypto/tls"
	"net"
)

// AuthConfig 认证配置
type AuthConfig struct {
	Username string
	Password string
}

// Transport 传输层接口 - 最小化设计，只为支持多种传输协议
type Transport interface {
	// 服务器端：监听并处理连接（🆕 支持 TLS 配置）
	ListenAndServe(addr string, handler func(Connection)) error
	ListenAndServeWithTLS(addr string, handler func(Connection), tlsConfig *tls.Config) error
	// 客户端：连接到服务器（支持配置）
	DialWithConfig(addr string, config *ClientConfig) (Connection, error)
	// 关闭传输层
	Close() error
}

// Connection 连接接口 - 简化的连接抽象
type Connection interface {
	// 写入消息（JSON 或 字节数据）
	WriteMessage(data []byte) error
	WriteJSON(v interface{}) error
	// 读取消息
	ReadMessage() ([]byte, error)
	ReadJSON(v interface{}) error
	// 连接管理
	Close() error
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	// 客户端信息 - 所有传输层都必须实现
	GetClientID() string
	GetGroupID() string
}

// ClientConfig 客户端配置 - 从 v1 复制必要的配置
type ClientConfig struct {
	ClientID   string
	GroupID    string
	Username   string
	Password   string
	TLSCert    string
	TLSConfig  *tls.Config
	SkipVerify bool
}

// ConnectionHandler 连接处理函数类型
type ConnectionHandler func(Connection)
