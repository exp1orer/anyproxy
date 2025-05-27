package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
)

// httpProxy implements the GatewayProxy interface for HTTP/HTTPS protocol
type httpProxy struct {
	config     *config.HTTPConfig
	server     *http.Server
	dialFunc   ProxyDialer
	listenAddr string
	listener   net.Listener
}

// NewHTTPProxy creates a new HTTP/HTTPS proxy
func NewHTTPProxy(cfg *config.HTTPConfig, dialFunc ProxyDialer) (GatewayProxy, error) {
	proxy := &httpProxy{
		config:     cfg,
		dialFunc:   dialFunc,
		listenAddr: cfg.ListenAddr,
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
		log.Printf("Starting HTTP proxy server on %s", h.listenAddr)
		if err := h.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP proxy server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the HTTP proxy server
func (h *httpProxy) Stop() error {
	log.Printf("Stopping HTTP proxy server on %s", h.listenAddr)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.server.Shutdown(ctx); err != nil {
		log.Printf("HTTP proxy server shutdown error: %v", err)
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
	if h.dialFunc == nil {
		return nil, fmt.Errorf("no dial function provided")
	}
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
	// Check authentication if configured
	if h.config.AuthUsername != "" && h.config.AuthPassword != "" {
		if !h.authenticate(r) {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
	}

	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}

	// Handle regular HTTP requests
	h.handleHTTPRequest(w, r)
}

// authenticate checks proxy authentication
func (h *httpProxy) authenticate(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	// Parse Basic authentication
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}

	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return false
	}

	username, password := parts[0], parts[1]
	return username == h.config.AuthUsername && password == h.config.AuthPassword
}

// handleConnect handles HTTPS CONNECT requests for tunneling
func (h *httpProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Extract target host and port
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":443" // Default HTTPS port
	}

	log.Printf("CONNECT request to %s", host)

	// Hijack the connection first to handle raw TCP tunneling
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Hijacking not supported")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Failed to hijack connection: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Create connection to target through the dial function
	targetConn, err := h.dialFunc(r.Context(), "tcp", host)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", host, err)
		// Send error response manually since we've hijacked the connection
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established response manually
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Failed to send CONNECT response: %v", err)
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

	log.Printf("CONNECT tunnel to %s closed", host)
}

// handleHTTPRequest handles regular HTTP requests (non-CONNECT)
func (h *httpProxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
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

	log.Printf("HTTP request to %s", targetURL.String())

	// Create connection to target
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		if targetURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	targetConn, err := h.dialFunc(r.Context(), "tcp", host)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", host, err)
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
		log.Printf("Failed to write request to target: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read response from target server
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, r)
	if err != nil {
		log.Printf("Failed to read response from target: %v", err)
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
		log.Printf("Failed to copy response body: %v", err)
	}

	log.Printf("HTTP request to %s completed", targetURL.String())
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
				log.Printf("Transfer %s write error: %v (transferred %d bytes)", direction, writeErr, totalBytes)
				return
			}
		}

		if err != nil {
			if err != io.EOF {
				log.Printf("Transfer %s read error: %v (transferred %d bytes)", direction, err, totalBytes)
			} else {
				log.Printf("Transfer %s completed: %d bytes", direction, totalBytes)
			}
			return
		}
	}
}
