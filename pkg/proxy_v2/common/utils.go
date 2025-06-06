package common

import (
	"github.com/rs/xid"
)

// GenerateConnID 生成唯一的连接 ID
func GenerateConnID() string {
	// 使用 xid 生成唯一的连接 ID
	// Length: 20 characters
	return xid.New().String()
}
