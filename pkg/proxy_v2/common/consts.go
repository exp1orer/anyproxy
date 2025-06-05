package common

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
