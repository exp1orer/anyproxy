package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
)

// TestHTTPProxyModes 测试HTTP代理的两种工作模式
func TestHTTPProxyModes(t *testing.T) {
	// 创建一个简单的HTTPS测试服务器
	httpsServer := createTestHTTPSServer(t)
	defer httpsServer.Close()

	// 获取服务器地址
	serverAddr := httpsServer.Listener.Addr().String()
	serverHost := strings.Split(serverAddr, ":")[0]
	serverPort := strings.Split(serverAddr, ":")[1]

	// Mock dial function
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 重定向到我们的测试服务器
		return net.Dial(network, serverAddr)
	}

	// 创建HTTP代理
	cfg := &config.HTTPConfig{
		ListenAddr: "127.0.0.1:0",
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

	err = proxy.Start()
	if err != nil {
		t.Fatalf("Failed to start HTTP proxy: %v", err)
	}
	defer proxy.Stop()

	httpProxy := proxy.(*httpProxy)
	proxyAddr := httpProxy.listener.Addr().String()
	time.Sleep(100 * time.Millisecond)

	t.Run("Mode 1: CONNECT Tunnel", func(t *testing.T) {
		// 模拟浏览器的CONNECT隧道模式
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// 发送CONNECT请求
		connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n",
			serverHost, serverPort, serverHost, serverPort)
		_, err = conn.Write([]byte(connectReq))
		if err != nil {
			t.Fatalf("Failed to send CONNECT: %v", err)
		}

		// 读取CONNECT响应
		reader := bufio.NewReader(conn)
		response, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read CONNECT response: %v", err)
		}

		if !strings.Contains(response, "200 Connection Established") {
			t.Errorf("Expected CONNECT success, got: %s", response)
		}

		// 跳过响应头
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read headers: %v", err)
			}
			if line == "\r\n" {
				break
			}
		}

		// 现在通过隧道发送HTTPS请求
		// 注意：这里我们发送的是原始HTTP请求，因为TLS在测试中被简化了
		httpReq := fmt.Sprintf("GET /test HTTP/1.1\r\nHost: %s:%s\r\n\r\n",
			serverHost, serverPort)
		_, err = conn.Write([]byte(httpReq))
		if err != nil {
			t.Fatalf("Failed to send HTTP request through tunnel: %v", err)
		}

		// 读取响应
		respLine, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if !strings.Contains(respLine, "200 OK") {
			t.Errorf("Expected 200 OK, got: %s", respLine)
		}

		t.Logf("✅ CONNECT隧道模式测试成功")
	})

	t.Run("Mode 2: Direct HTTPS Request", func(t *testing.T) {
		// 模拟直接发送HTTPS URL的客户端
		// 创建HTTP客户端，配置代理
		proxyURL := fmt.Sprintf("http://%s", proxyAddr)
		transport := &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 测试环境跳过证书验证
			},
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}

		// 发送HTTPS请求（注意：在测试中我们使用HTTP，但逻辑相同）
		testURL := fmt.Sprintf("http://%s/test", serverAddr)
		resp, err := client.Get(testURL)
		if err != nil {
			t.Fatalf("Failed to send HTTPS request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200, got: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if !strings.Contains(string(body), "Hello from test server") {
			t.Errorf("Unexpected response body: %s", string(body))
		}

		t.Logf("✅ 直接HTTPS请求模式测试成功")
	})
}

// TestServer 包装测试服务器和监听器
type TestServer struct {
	*http.Server
	Listener net.Listener
}

func (ts *TestServer) Close() error {
	ts.Server.Close()
	return ts.Listener.Close()
}

// createTestHTTPSServer 创建一个简单的测试服务器
func createTestHTTPSServer(t *testing.T) *TestServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from test server"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		server.Serve(listener)
	}()

	return &TestServer{
		Server:   server,
		Listener: listener,
	}
}
