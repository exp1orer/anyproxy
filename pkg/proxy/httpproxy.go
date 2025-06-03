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
		slog.Error("HTTP proxy creation failed: config cannot be nil")
		return nil, fmt.Errorf("config cannot be nil")
	}
	if dialFunc == nil {
		slog.Error("HTTP proxy creation failed: dialFunc cannot be nil")
		return nil, fmt.Errorf("dialFunc cannot be nil")
	}

	slog.Info("Creating new HTTP proxy",
		"listen_addr", cfg.ListenAddr,
		"auth_enabled", cfg.AuthUsername != "",
		"group_extraction_enabled", groupExtractor != nil)

	proxy := &httpProxy{
		config:         cfg,
		dialFunc:       dialFunc,
		groupExtractor: groupExtractor,
		listenAddr:     cfg.ListenAddr,
	}

	slog.Debug("Configuring HTTP server",
		"listen_addr", proxy.listenAddr,
		"read_timeout", "30s",
		"write_timeout", "30s",
		"idle_timeout", "60s")

	// Create HTTP server with custom handler
	// Don't use ServeMux as it doesn't handle CONNECT requests properly
	proxy.server = &http.Server{
		Addr:         proxy.listenAddr,
		Handler:      proxy, // Use the proxy itself as the handler
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("HTTP proxy created successfully",
		"listen_addr", cfg.ListenAddr,
		"auth_username", cfg.AuthUsername)

	return proxy, nil
}

// Start starts the HTTP proxy server
func (h *httpProxy) Start() error {
	slog.Info("Starting HTTP proxy server", "listen_addr", h.listenAddr)
	startTime := time.Now()

	// Create listener
	slog.Debug("Creating TCP listener", "address", h.listenAddr)
	listener, err := net.Listen("tcp", h.listenAddr)
	if err != nil {
		slog.Error("Failed to create TCP listener for HTTP proxy",
			"listen_addr", h.listenAddr,
			"error", err)
		return fmt.Errorf("failed to listen on %s: %v", h.listenAddr, err)
	}
	h.listener = listener
	slog.Debug("TCP listener created successfully", "listen_addr", h.listenAddr)

	// Start HTTP proxy server in a separate goroutine
	go func() {
		elapsed := time.Since(startTime)
		slog.Info("HTTP proxy server starting to serve requests",
			"listen_addr", h.listenAddr,
			"startup_duration", elapsed)
		if err := h.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP proxy server terminated unexpectedly",
				"listen_addr", h.listenAddr,
				"error", err)
		} else {
			slog.Info("HTTP proxy server stopped", "listen_addr", h.listenAddr)
		}
	}()

	slog.Info("HTTP proxy server started successfully",
		"listen_addr", h.listenAddr,
		"startup_duration", time.Since(startTime))

	return nil
}

// Stop stops the HTTP proxy server
func (h *httpProxy) Stop() error {
	slog.Info("Initiating HTTP proxy server shutdown", "listen_addr", h.listenAddr)
	stopTime := time.Now()

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	slog.Debug("Attempting graceful shutdown",
		"listen_addr", h.listenAddr,
		"timeout", "5s")

	if err := h.server.Shutdown(ctx); err != nil {
		slog.Error("HTTP proxy server graceful shutdown failed",
			"listen_addr", h.listenAddr,
			"error", err)
		// Force close if graceful shutdown fails
		if h.listener != nil {
			slog.Warn("Forcing listener close after failed graceful shutdown",
				"listen_addr", h.listenAddr)
			return h.listener.Close()
		}
		return err
	}

	elapsed := time.Since(stopTime)
	slog.Info("HTTP proxy server shutdown completed",
		"listen_addr", h.listenAddr,
		"shutdown_duration", elapsed)

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

	slog.Debug("Received HTTP proxy request",
		"request_id", requestID,
		"method", r.Method,
		"host", r.Host,
		"url", r.URL.String(),
		"remote_addr", r.RemoteAddr,
		"user_agent", r.Header.Get("User-Agent"))

	var userCtx *UserContext

	// Check authentication if configured
	if h.config.AuthUsername != "" && h.config.AuthPassword != "" {
		slog.Debug("Authentication required, checking credentials",
			"request_id", requestID,
			"remote_addr", r.RemoteAddr)

		username, _, authenticated := h.authenticateAndExtractUser(r)
		if !authenticated {
			slog.Warn("HTTP proxy authentication failed",
				"request_id", requestID,
				"remote_addr", r.RemoteAddr,
				"method", r.Method,
				"host", r.Host)
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}

		// Create user context with group information
		groupID := ""
		if h.groupExtractor != nil {
			groupID = h.groupExtractor(username)
			slog.Debug("Extracted group ID from username",
				"request_id", requestID,
				"username", username,
				"group_id", groupID)
		}
		userCtx = &UserContext{
			Username: username,
			GroupID:  groupID,
		}

		slog.Debug("HTTP proxy authentication successful",
			"request_id", requestID,
			"username", username,
			"group_id", groupID,
			"remote_addr", r.RemoteAddr)
	} else {
		slog.Debug("No authentication required", "request_id", requestID)
	}

	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		slog.Info("Handling HTTPS CONNECT request",
			"request_id", requestID,
			"host", r.Host,
			"remote_addr", r.RemoteAddr,
			"username", func() string {
				if userCtx != nil {
					return userCtx.Username
				}
				return ""
			}())
		h.handleConnect(w, r, userCtx, requestID)
		return
	}

	// Handle regular HTTP requests
	slog.Info("Handling HTTP request",
		"request_id", requestID,
		"method", r.Method,
		"url", r.URL.String(),
		"remote_addr", r.RemoteAddr,
		"username", func() string {
			if userCtx != nil {
				return userCtx.Username
			}
			return ""
		}())
	h.handleHTTPRequest(w, r, userCtx, requestID)

	elapsed := time.Since(requestStart)
	slog.Info("HTTP proxy request completed",
		"request_id", requestID,
		"method", r.Method,
		"host", r.Host,
		"duration", elapsed,
		"remote_addr", r.RemoteAddr)
}

// authenticateAndExtractUser checks proxy authentication and returns username, password, and auth status
func (h *httpProxy) authenticateAndExtractUser(r *http.Request) (string, string, bool) {
	slog.Debug("Checking proxy authentication",
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"host", r.Host)

	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		slog.Debug("No proxy authorization header found",
			"remote_addr", r.RemoteAddr)
		return "", "", false
	}

	// Parse Basic authentication
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		slog.Warn("Invalid proxy authorization header format",
			"remote_addr", r.RemoteAddr,
			"auth_type", strings.SplitN(auth, " ", 2)[0])
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		slog.Warn("Failed to decode proxy authorization header",
			"remote_addr", r.RemoteAddr,
			"error", err)
		return "", "", false
	}

	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		slog.Warn("Invalid credentials format in proxy authorization",
			"remote_addr", r.RemoteAddr)
		return "", "", false
	}

	username, password := parts[0], parts[1]

	// Extract the base username (without group_id) for authentication
	baseUsername := extractBaseUsername(username)

	// Authenticate using the base username and provided password
	authenticated := baseUsername == h.config.AuthUsername && password == h.config.AuthPassword

	if authenticated {
		slog.Debug("Proxy authentication successful",
			"remote_addr", r.RemoteAddr,
			"username", username,
			"base_username", baseUsername)
	} else {
		slog.Warn("Proxy authentication failed",
			"remote_addr", r.RemoteAddr,
			"username", username,
			"base_username", baseUsername)
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
	connectStart := time.Now()

	// Extract target host and port
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":443" // Default HTTPS port
		slog.Debug("Added default HTTPS port",
			"request_id", requestID,
			"original_host", r.URL.Host,
			"target_host", host)
	}

	slog.Info("Processing CONNECT request",
		"request_id", requestID,
		"target_host", host,
		"remote_addr", r.RemoteAddr,
		"user_context", userCtx)

	// Hijack the connection first to handle raw TCP tunneling
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("Hijacking not supported by response writer",
			"request_id", requestID,
			"target_host", host)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	slog.Debug("Hijacking HTTP connection for tunnel", "request_id", requestID)
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		slog.Error("Failed to hijack HTTP connection",
			"request_id", requestID,
			"target_host", host,
			"error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	slog.Debug("HTTP connection hijacked successfully",
		"request_id", requestID,
		"client_addr", clientConn.RemoteAddr())

	// Create context with user information
	ctx := r.Context()
	if userCtx != nil {
		ctx = context.WithValue(ctx, "user", userCtx)
		slog.Debug("Added user context to dial context",
			"request_id", requestID,
			"username", userCtx.Username,
			"group_id", userCtx.GroupID)
	}

	// Create connection to target through the dial function
	slog.Debug("Dialing target host",
		"request_id", requestID,
		"target_host", host)
	dialStart := time.Now()
	targetConn, err := h.dialFunc(ctx, "tcp", host)
	dialDuration := time.Since(dialStart)

	if err != nil {
		slog.Error("Failed to connect to target host",
			"request_id", requestID,
			"target_host", host,
			"dial_duration", dialDuration,
			"error", err)
		// Send error response manually since we've hijacked the connection
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	slog.Debug("Connected to target host successfully",
		"request_id", requestID,
		"target_host", host,
		"dial_duration", dialDuration,
		"target_addr", targetConn.RemoteAddr())

	// Send 200 Connection Established response manually
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		slog.Error("Failed to send CONNECT response to client",
			"request_id", requestID,
			"target_host", host,
			"error", err)
		return
	}
	slog.Debug("Sent CONNECT response to client", "request_id", requestID)

	// Handle any buffered data from the client
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		bufferedBytes := clientBuf.Reader.Buffered()
		bufferedData := make([]byte, bufferedBytes)
		clientBuf.Reader.Read(bufferedData)
		targetConn.Write(bufferedData)
		slog.Debug("Forwarded buffered client data",
			"request_id", requestID,
			"bytes", bufferedBytes)
	}

	setupDuration := time.Since(connectStart)
	slog.Info("CONNECT tunnel established",
		"request_id", requestID,
		"target_host", host,
		"setup_duration", setupDuration,
		"dial_duration", dialDuration)

	// Start bidirectional data transfer
	transferStart := time.Now()
	go h.transfer(targetConn, clientConn, "target->client", requestID)
	h.transfer(clientConn, targetConn, "client->target", requestID)

	transferDuration := time.Since(transferStart)
	totalDuration := time.Since(connectStart)
	slog.Info("CONNECT tunnel closed",
		"request_id", requestID,
		"target_host", host,
		"transfer_duration", transferDuration,
		"total_duration", totalDuration)
}

// handleHTTPRequest handles regular HTTP requests (non-CONNECT)
func (h *httpProxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request, userCtx *UserContext, requestID string) {
	requestStart := time.Now()

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
		slog.Debug("Constructed absolute URL from relative URL",
			"request_id", requestID,
			"original_url", r.URL.String(),
			"target_url", targetURL.String())
	}

	slog.Info("Processing HTTP request",
		"request_id", requestID,
		"method", r.Method,
		"target_url", targetURL.String(),
		"remote_addr", r.RemoteAddr,
		"user_context", userCtx)

	// Create connection to target
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		if targetURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
		slog.Debug("Added default port to host",
			"request_id", requestID,
			"original_host", targetURL.Host,
			"target_host", host,
			"scheme", targetURL.Scheme)
	}

	// Create context with user information
	ctx := r.Context()
	if userCtx != nil {
		ctx = context.WithValue(ctx, "user", userCtx)
	}

	slog.Debug("Dialing target server",
		"request_id", requestID,
		"target_host", host)
	dialStart := time.Now()
	targetConn, err := h.dialFunc(ctx, "tcp", host)
	dialDuration := time.Since(dialStart)

	if err != nil {
		slog.Error("Failed to connect to target server",
			"request_id", requestID,
			"target_host", host,
			"dial_duration", dialDuration,
			"error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	slog.Debug("Connected to target server successfully",
		"request_id", requestID,
		"target_host", host,
		"dial_duration", dialDuration)

	// For HTTPS, wrap with TLS
	if targetURL.Scheme == "https" {
		slog.Debug("Wrapping connection with TLS",
			"request_id", requestID,
			"server_name", strings.Split(host, ":")[0])
		tlsConn := tls.Client(targetConn, &tls.Config{
			ServerName: strings.Split(host, ":")[0],
		})
		targetConn = tlsConn
	}

	// Remove proxy-specific headers
	originalProxyAuth := r.Header.Get("Proxy-Authorization")
	originalProxyConn := r.Header.Get("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")

	// Set Connection header for HTTP/1.1
	r.Header.Set("Connection", "close")

	slog.Debug("Modified request headers for forwarding",
		"request_id", requestID,
		"removed_proxy_auth", originalProxyAuth != "",
		"removed_proxy_conn", originalProxyConn != "")

	// Write request to target server
	slog.Debug("Sending request to target server", "request_id", requestID)
	writeStart := time.Now()
	if err := r.Write(targetConn); err != nil {
		writeDuration := time.Since(writeStart)
		slog.Error("Failed to write request to target server",
			"request_id", requestID,
			"target_host", host,
			"write_duration", writeDuration,
			"error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	writeDuration := time.Since(writeStart)
	slog.Debug("Request sent to target server",
		"request_id", requestID,
		"write_duration", writeDuration)

	// Read response from target server
	slog.Debug("Reading response from target server", "request_id", requestID)
	targetReader := bufio.NewReader(targetConn)
	readStart := time.Now()
	resp, err := http.ReadResponse(targetReader, r)
	readDuration := time.Since(readStart)

	if err != nil {
		slog.Error("Failed to read response from target server",
			"request_id", requestID,
			"target_host", host,
			"read_duration", readDuration,
			"error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	slog.Debug("Response received from target server",
		"request_id", requestID,
		"status_code", resp.StatusCode,
		"content_length", resp.ContentLength,
		"read_duration", readDuration)

	// Copy response headers
	headerCount := 0
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
			headerCount++
		}
	}
	slog.Debug("Copied response headers",
		"request_id", requestID,
		"header_count", headerCount)

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	slog.Debug("Copying response body to client", "request_id", requestID)
	copyStart := time.Now()
	bytesWritten, err := io.Copy(w, resp.Body)
	copyDuration := time.Since(copyStart)

	if err != nil {
		slog.Error("Failed to copy response body to client",
			"request_id", requestID,
			"bytes_written", bytesWritten,
			"copy_duration", copyDuration,
			"error", err)
	} else {
		slog.Debug("Response body copied successfully",
			"request_id", requestID,
			"bytes_written", bytesWritten,
			"copy_duration", copyDuration)
	}

	totalDuration := time.Since(requestStart)
	slog.Info("HTTP request processing completed",
		"request_id", requestID,
		"method", r.Method,
		"target_url", targetURL.String(),
		"status_code", resp.StatusCode,
		"bytes_written", bytesWritten,
		"total_duration", totalDuration,
		"dial_duration", dialDuration,
		"write_duration", writeDuration,
		"read_duration", readDuration,
		"copy_duration", copyDuration)
}

// transfer copies data between two connections
func (h *httpProxy) transfer(dst, src net.Conn, direction string, requestID string) {
	slog.Debug("Starting data transfer",
		"request_id", requestID,
		"direction", direction,
		"src_addr", src.RemoteAddr(),
		"dst_addr", dst.RemoteAddr())

	buffer := make([]byte, 32*1024) // 32KB buffer
	totalBytes := int64(0)
	transferCount := 0
	startTime := time.Now()

	defer func() {
		duration := time.Since(startTime)
		slog.Info("Data transfer completed",
			"request_id", requestID,
			"direction", direction,
			"total_bytes", totalBytes,
			"transfer_operations", transferCount,
			"duration", duration,
			"avg_speed_mbps", func() float64 {
				if duration.Seconds() > 0 {
					return float64(totalBytes) / duration.Seconds() / 1024 / 1024
				}
				return 0
			}())
	}()

	for {
		// Set read timeout
		src.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := src.Read(buffer)
		transferCount++

		if n > 0 {
			totalBytes += int64(n)

			// Only log for large transfers or periodic updates
			if totalBytes%1000000 == 0 || n > 50000 { // Log every 1MB or large chunks
				slog.Debug("Data transfer progress",
					"request_id", requestID,
					"direction", direction,
					"bytes_this_read", n,
					"total_bytes", totalBytes,
					"transfer_count", transferCount)
			}

			// Set write timeout
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))

			_, writeErr := dst.Write(buffer[:n])
			if writeErr != nil {
				slog.Error("Data transfer write error",
					"request_id", requestID,
					"direction", direction,
					"bytes_written_before_error", totalBytes,
					"error", writeErr)
				return
			}
		}

		if err != nil {
			if err != io.EOF {
				slog.Debug("Data transfer read error",
					"request_id", requestID,
					"direction", direction,
					"total_bytes", totalBytes,
					"error", err)
			} else {
				slog.Debug("Data transfer ended (EOF)",
					"request_id", requestID,
					"direction", direction,
					"total_bytes", totalBytes)
			}
			return
		}
	}
}
