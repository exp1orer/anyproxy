package common

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// mockConn 实现 net.Conn 接口用于测试
type mockConn struct{}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestConnWrapperConcurrentAccess 测试并发访问 ConnID
func TestConnWrapperConcurrentAccess(t *testing.T) {
	wrapper := NewConnWrapper(&mockConn{}, "tcp", "127.0.0.1:8080")

	// 初始设置
	wrapper.SetConnID("initial-id")

	// 并发读写测试
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// 启动多个写入者
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				connID := fmt.Sprintf("conn-%d-%d", id, j)
				wrapper.SetConnID(connID)

				// 立即读取验证
				readID := wrapper.GetConnID()
				if readID == "" {
					errors <- fmt.Errorf("writer %d: got empty conn ID", id)
				}
			}
		}(i)
	}

	// 启动多个读取者
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				connID := wrapper.GetConnID()
				if connID == "" {
					errors <- fmt.Errorf("reader %d: got empty conn ID", id)
				}
			}
		}(i)
	}

	// 等待所有 goroutine 完成
	wg.Wait()
	close(errors)

	// 检查错误
	for err := range errors {
		t.Error(err)
	}
}

// TestConnWrapperAddressMethods 测试地址方法
func TestConnWrapperAddressMethods(t *testing.T) {
	tests := []struct {
		name           string
		network        string
		remoteAddress  string
		wantLocalPort  int
		wantRemotePort int
	}{
		{
			name:           "valid TCP address",
			network:        "tcp",
			remoteAddress:  "192.168.1.1:8080",
			wantLocalPort:  0,
			wantRemotePort: 8080,
		},
		{
			name:           "valid UDP address",
			network:        "udp",
			remoteAddress:  "10.0.0.1:53",
			wantLocalPort:  0,
			wantRemotePort: 53,
		},
		{
			name:           "invalid address format",
			network:        "tcp",
			remoteAddress:  "invalid-address",
			wantLocalPort:  0,
			wantRemotePort: 80, // 默认端口
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewConnWrapper(&mockConn{}, tt.network, tt.remoteAddress)

			// 测试本地地址
			localAddr := wrapper.LocalAddr()
			if localAddr == nil {
				t.Error("LocalAddr() returned nil")
			}

			// 测试远程地址
			remoteAddr := wrapper.RemoteAddr()
			if remoteAddr == nil {
				t.Error("RemoteAddr() returned nil")
			}

			// 验证端口
			switch addr := remoteAddr.(type) {
			case *net.TCPAddr:
				if addr.Port != tt.wantRemotePort {
					t.Errorf("TCP port = %d, want %d", addr.Port, tt.wantRemotePort)
				}
			case *net.UDPAddr:
				if addr.Port != tt.wantRemotePort {
					t.Errorf("UDP port = %d, want %d", addr.Port, tt.wantRemotePort)
				}
			}
		})
	}
}

// BenchmarkConnWrapperGetConnID 基准测试读取性能
func BenchmarkConnWrapperGetConnID(b *testing.B) {
	wrapper := NewConnWrapper(&mockConn{}, "tcp", "127.0.0.1:8080")
	wrapper.SetConnID("benchmark-conn-id")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = wrapper.GetConnID()
		}
	})
}

// BenchmarkConnWrapperSetConnID 基准测试写入性能
func BenchmarkConnWrapperSetConnID(b *testing.B) {
	wrapper := NewConnWrapper(&mockConn{}, "tcp", "127.0.0.1:8080")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			wrapper.SetConnID(fmt.Sprintf("conn-%d", i))
			i++
		}
	})
}
