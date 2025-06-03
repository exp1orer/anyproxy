package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
)

// httpProxy implements the GatewayProxy interface for HTTP/HTTPS protocol
type httpProxy struct {
	config         *config.HTTPConfig
	server         *http.Server
	dialFunc       Dialer
	groupExtractor GroupExtractor
	listenAddr     string
	listener       net.Listener
}

// NewHTTPProxy creates a new HTTP/HTTPS proxy
func NewHTTPProxy(cfg *config.HTTPConfig, dialFunc Dialer) (GatewayProxy, error) {
	return NewHTTPProxyWithAuth(cfg, dialFunc, nil)
}

// NewHTTPProxyWithAuth creates a new HTTP/HTTPS proxy with authentication support
func NewHTTPProxyWithAuth(cfg *config.HTTPConfig, dialFunc Dialer, groupExtractor GroupExtractor) (GatewayProxy, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if dialFunc == nil {
		return nil, fmt.Errorf("dialFunc cannot be nil")
	}

	proxy := &httpProxy{
		config:         cfg,
		dialFunc:       dialFunc,
		groupExtractor: groupExtractor,
		listenAddr:     cfg.ListenAddr,
	}

	// Create HTTP server with custom handler
	// Don't use ServeMux as it doesn't handle CONNECT requests properly
	proxy.server = &http.Server{
		Addr:         proxy.listenAddr,
		Handler:      proxy, // Use the proxy itself as the handler
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return proxy, nil
}

// Start starts the HTTP proxy server
func (h *httpProxy) Start() error {
	// Create listener
	listener, err := net.Listen("tcp", h.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", h.listenAddr, err)
	}
	h.listener = listener

	// Start HTTP proxy server in a separate goroutine
	go func() {
		slog.Info("Starting HTTP proxy server", "listen_addr", h.listenAddr)
		if err := h.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP proxy server error", "error", err)
		}
	}()

	return nil
}

// Stop stops the HTTP proxy server
func (h *httpProxy) Stop() error {
	slog.Info("Stopping HTTP proxy server", "listen_addr", h.listenAddr)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.server.Shutdown(ctx); err != nil {
		slog.Error("HTTP proxy server shutdown error", "error", err)
		// Force close if graceful shutdown fails
		if h.listener != nil {
			return h.listener.Close()
		}
		return err
	}

	return nil
}

// DialConn implements the GatewayProxy interface by using the dialFunc
func (h *httpProxy) DialConn(network, addr string) (net.Conn, error) {
	return h.dialFunc(context.Background(), network, addr)
}

// SetListenAddr sets the address on which the HTTP proxy server will listen
func (h *httpProxy) SetListenAddr(addr string) {
	h.listenAddr = addr
}

// ServeHTTP implements the http.Handler interface
func (h *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handleHTTP(w, r)
}

// handleHTTP handles both HTTP and HTTPS requests
func (h *httpProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var userCtx *UserContext

	// Check authentication if configured
	if h.config.AuthUsername != "" && h.config.AuthPassword != "" {
		username, _, authenticated := h.authenticateAndExtractUser(r)
		if !authenticated {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}

		// Create user context with group information
		groupID := ""
		if h.groupExtractor != nil {
			groupID = h.groupExtractor(username)
		}
		userCtx = &UserContext{
			Username: username,
			GroupID:  groupID,
		}
	}

	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r, userCtx)
		return
	}

	// Handle regular HTTP requests
	h.handleHTTPRequest(w, r, userCtx)
}

// authenticateAndExtractUser checks proxy authentication and returns username, password, and auth status
func (h *httpProxy) authenticateAndExtractUser(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}

	// Parse Basic authentication
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}

	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	username, password := parts[0], parts[1]

	// Extract the base username (without group_id) for authentication
	baseUsername := extractBaseUsername(username)

	// Authenticate using the base username and provided password
	authenticated := baseUsername == h.config.AuthUsername && password == h.config.AuthPassword

	return username, password, authenticated
}

// authenticate checks proxy authentication (kept for backward compatibility)
func (h *httpProxy) authenticate(r *http.Request) bool {
	_, _, authenticated := h.authenticateAndExtractUser(r)
	return authenticated
}

// handleConnect handles HTTPS CONNECT requests for tunneling
func (h *httpProxy) handleConnect(w http.ResponseWriter, r *http.Request, userCtx *UserContext) {
	// Extract target host and port
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":443" // Default HTTPS port
	}

	slog.Info("CONNECT request", "host", host, "user", userCtx)

	// Hijack the connection first to handle raw TCP tunneling
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("Hijacking not supported")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		slog.Error("Failed to hijack connection", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Create context with user information
	ctx := r.Context()
	if userCtx != nil {
		ctx = context.WithValue(ctx, "user", userCtx)
	}

	// Create connection to target through the dial function
	targetConn, err := h.dialFunc(ctx, "tcp", host)
	if err != nil {
		slog.Error("Failed to connect", "host", host, "error", err)
		// Send error response manually since we've hijacked the connection
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established response manually
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		slog.Error("Failed to send CONNECT response", "error", err)
		return
	}

	// Handle any buffered data from the client
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		bufferedData := make([]byte, clientBuf.Reader.Buffered())
		clientBuf.Reader.Read(bufferedData)
		targetConn.Write(bufferedData)
	}

	// Start bidirectional data transfer
	go h.transfer(targetConn, clientConn, "target->client")
	h.transfer(clientConn, targetConn, "client->target")

	slog.Info("CONNECT tunnel closed", "host", host)
}

// handleHTTPRequest handles regular HTTP requests (non-CONNECT)
func (h *httpProxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request, userCtx *UserContext) {
	// Parse target URL
	targetURL := r.URL
	if !targetURL.IsAbs() {
		// If URL is not absolute, construct it from Host header
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		targetURL = &url.URL{
			Scheme:   scheme,
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
	}

	slog.Info("HTTP request", "url", targetURL.String(), "user", userCtx)

	// Create connection to target
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		if targetURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Create context with user information
	ctx := r.Context()
	if userCtx != nil {
		ctx = context.WithValue(ctx, "user", userCtx)
	}

	targetConn, err := h.dialFunc(ctx, "tcp", host)
	if err != nil {
		slog.Error("Failed to connect", "host", host, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// For HTTPS, wrap with TLS
	if targetURL.Scheme == "https" {
		tlsConn := tls.Client(targetConn, &tls.Config{
			ServerName: strings.Split(host, ":")[0],
		})
		targetConn = tlsConn
	}

	// Remove proxy-specific headers
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")

	// Set Connection header for HTTP/1.1
	r.Header.Set("Connection", "close")

	// Write request to target server
	if err := r.Write(targetConn); err != nil {
		slog.Error("Failed to write request to target", "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read response from target server
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, r)
	if err != nil {
		slog.Error("Failed to read response from target", "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		slog.Error("Failed to copy response body", "error", err)
	}

	slog.Info("HTTP request completed", "url", targetURL.String())
}

// transfer copies data between two connections
func (h *httpProxy) transfer(dst, src net.Conn, direction string) {
	buffer := make([]byte, 32*1024) // 32KB buffer
	totalBytes := int64(0)

	for {
		// Set read timeout
		src.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := src.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)

			// Set write timeout
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))

			_, writeErr := dst.Write(buffer[:n])
			if writeErr != nil {
				slog.Error("Transfer write error", "direction", direction, "error", writeErr, "transferred_bytes", totalBytes)
				return
			}
		}

		if err != nil {
			if err != io.EOF {
				slog.Error("Transfer read error", "direction", direction, "error", err, "transferred_bytes", totalBytes)
			} else {
				slog.Debug("Transfer completed", "direction", direction, "transferred_bytes", totalBytes)
			}
			return
		}
	}
}
