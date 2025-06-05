package proxy

// Message type constants
const (
	MsgTypeConnect         = "connect"
	MsgTypeData            = "data"
	MsgTypeClose           = "close"
	MsgTypeConnectResponse = "connect_response"
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

// Test constants
const (
	TestConnID   = "test-conn"
	TestClientID = "test-client"
)

const writeBufSize = 1000
