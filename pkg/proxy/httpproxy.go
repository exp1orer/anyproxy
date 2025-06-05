package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
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
		logger.Error("HTTP proxy creation failed: config cannot be nil")
		return nil, fmt.Errorf("config cannot be nil")
	}
	if dialFunc == nil {
		logger.Error("HTTP proxy creation failed: dialFunc cannot be nil")
		return nil, fmt.Errorf("dialFunc cannot be nil")
	}

	logger.Info("Creating HTTP proxy", "addr", cfg.ListenAddr, "auth", cfg.AuthUsername != "")

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

	logger.Info("HTTP proxy created", "addr", cfg.ListenAddr)

	return proxy, nil
}

// Start starts the HTTP proxy server
func (h *httpProxy) Start() error {
	logger.Info("Starting HTTP proxy server", "addr", h.listenAddr)

	// Create listener
	listener, err := net.Listen("tcp", h.listenAddr)
	if err != nil {
		logger.Error("Failed to create TCP listener", "addr", h.listenAddr, "err", err)
		return fmt.Errorf("failed to listen on %s: %v", h.listenAddr, err)
	}
	h.listener = listener

	// Start HTTP proxy server in a separate goroutine
	go func() {
		if err := h.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP proxy server error", "addr", h.listenAddr, "err", err)
		}
	}()

	logger.Info("HTTP proxy server started", "addr", h.listenAddr)
	return nil
}

// Stop stops the HTTP proxy server
func (h *httpProxy) Stop() error {
	logger.Info("Stopping HTTP proxy server", "addr", h.listenAddr)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.server.Shutdown(ctx); err != nil {
		logger.Error("HTTP proxy graceful shutdown failed", "addr", h.listenAddr, "err", err)
		// Force close if graceful shutdown fails
		if h.listener != nil {
			return h.listener.Close()
		}
		return err
	}

	logger.Info("HTTP proxy server stopped", "addr", h.listenAddr)
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
	requestStart := time.Now()
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())

	var userCtx *UserContext

	// Check authentication if configured
	if h.config.AuthUsername != "" && h.config.AuthPassword != "" {
		username, _, authenticated := h.authenticateAndExtractUser(r)
		if !authenticated {
			logger.Warn("HTTP proxy auth failed", "from", r.RemoteAddr, "method", r.Method, "host", r.Host)
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
		logger.Info("CONNECT request", "id", requestID, "host", r.Host, "from", r.RemoteAddr)
		h.handleConnect(w, r, userCtx, requestID)
		logger.Info("CONNECT completed", "id", requestID, "duration", time.Since(requestStart))
		return
	}

	// Handle regular HTTP requests
	logger.Info("HTTP request", "id", requestID, "method", r.Method, "url", r.URL.String(), "from", r.RemoteAddr)
	h.handleHTTPRequest(w, r, userCtx, requestID)
	logger.Info("HTTP completed", "id", requestID, "duration", time.Since(requestStart))
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
		logger.Warn("Invalid auth header format", "from", r.RemoteAddr)
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		logger.Warn("Failed to decode auth header", "from", r.RemoteAddr, "err", err)
		return "", "", false
	}

	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		logger.Warn("Invalid credentials format", "from", r.RemoteAddr)
		return "", "", false
	}

	username, password := parts[0], parts[1]

	// Extract the base username (without group_id) for authentication
	baseUsername := extractBaseUsername(username)

	// Authenticate using the base username and provided password
	authenticated := baseUsername == h.config.AuthUsername && password == h.config.AuthPassword

	if !authenticated {
		logger.Warn("Auth failed", "from", r.RemoteAddr, "user", username)
	}

	return username, password, authenticated
}

// authenticate checks proxy authentication (kept for backward compatibility)
func (h *httpProxy) authenticate(r *http.Request) bool {
	_, _, authenticated := h.authenticateAndExtractUser(r)
	return authenticated
}

// handleConnect handles HTTPS CONNECT requests for tunneling
func (h *httpProxy) handleConnect(w http.ResponseWriter, r *http.Request, userCtx *UserContext, requestID string) {
	// Extract target host and port
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":443" // Default HTTPS port
	}

	// Connect to target server via client dial function
	targetConn, err := h.dialFunc(r.Context(), "tcp", host)
	if err != nil {
		logger.Error("Failed to connect to target", "id", requestID, "host", host, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Get underlying connection for hijacking
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("Response writer does not support hijacking", "id", requestID)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Error("Failed to hijack connection", "id", requestID, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send successful response to client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		logger.Error("Failed to send 200 response", "id", requestID, "err", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Start bidirectional data transfer
	go h.transfer(targetConn, clientConn, "target->client", requestID)
	h.transfer(clientConn, targetConn, "client->target", requestID)
}

// handleHTTPRequest handles regular HTTP requests (non-CONNECT)
func (h *httpProxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request, userCtx *UserContext, requestID string) {
	// Parse target URL
	targetURL := r.URL
	if !targetURL.IsAbs() {
		// If URL is not absolute, construct it from Host header
		scheme := "http"
		if r.TLS != nil {
			scheme = SchemeHTTPS
		}
		targetURL = &url.URL{
			Scheme:   scheme,
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
	}

	// Create connection to target
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		if targetURL.Scheme == SchemeHTTPS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Create context with user information
	ctx := r.Context()
	if userCtx != nil {
		type userContextKey string
		const userKey userContextKey = "user"
		ctx = context.WithValue(ctx, userKey, userCtx)
	}

	targetConn, err := h.dialFunc(ctx, "tcp", host)
	if err != nil {
		logger.Error("Failed to dial target", "id", requestID, "host", host, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Wrap with TLS if HTTPS
	if targetURL.Scheme == SchemeHTTPS {
		tlsConfig := &tls.Config{
			ServerName: targetURL.Hostname(),
		}
		targetConn = tls.Client(targetConn, tlsConfig)
	}

	// Remove proxy-specific headers
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")
	r.Header.Set("Connection", "close")

	// Write request to target server
	if err := r.Write(targetConn); err != nil {
		logger.Error("Failed to write request", "id", requestID, "host", host, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read response from target server
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, r)
	if err != nil {
		logger.Error("Failed to read response", "id", requestID, "host", host, "err", err)
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
	bytesWritten, err := io.Copy(w, resp.Body)
	if err != nil {
		logger.Error("Failed to copy response", "id", requestID, "bytes", bytesWritten, "err", err)
	}
}

// transfer copies data between two connections
func (h *httpProxy) transfer(dst, src net.Conn, direction string, requestID string) {
	buffer := make([]byte, 32*1024) // 32KB buffer
	totalBytes := int64(0)

	defer func() {
		logger.Debug("Transfer done", "id", requestID, "dir", direction, "bytes", totalBytes)
	}()

	// Copy data from source to destination
	go func() {
		defer dst.Close()
		buf := make([]byte, 32*1024)
		for {
			src.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := src.Read(buf)
			if n > 0 {
				dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}()

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
				logger.Error("Transfer write error", "id", requestID, "dir", direction, "bytes", totalBytes, "err", writeErr)
				return
			}
		}

		if err != nil {
			if err != io.EOF {
				logger.Debug("Transfer read error", "id", requestID, "dir", direction, "bytes", totalBytes, "err", err)
			}
			return
		}
	}
}
