package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

// dialGRPCWithConfig connects to gRPC server with configuration
func (t *grpcTransport) dialGRPCWithConfig(addr string, config *transport.ClientConfig) (transport.Connection, error) {
	slog.Debug("Establishing gRPC connection to gateway",
		"client_id", config.ClientID,
		"gateway_addr", addr)

	// Set up connection options
	var opts []grpc.DialOption

	// 🚨 Fix: Configure gRPC client keepalive parameters to prevent unexpected connection drops
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                30 * time.Second, // Send keepalive ping every 30 seconds
		Timeout:             5 * time.Second,  // Keepalive response timeout
		PermitWithoutStream: true,             // Allow keepalive when no active streams
	}))

	// Configure TLS
	if config.TLSConfig != nil {
		creds := credentials.NewTLS(config.TLSConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
		slog.Debug("gRPC TLS configured", "client_id", config.ClientID)
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		slog.Debug("gRPC using insecure connection", "client_id", config.ClientID)
	}

	// Set connection timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	slog.Info("Connecting to gRPC endpoint",
		"client_id", config.ClientID,
		"addr", addr,
		"keepalive_time", "30s",
		"keepalive_timeout", "5s")

	// Establish gRPC connection
	conn, err := grpc.DialContext(ctx, addr, opts...)
	if err != nil {
		slog.Error("Failed to connect to gRPC server",
			"client_id", config.ClientID,
			"addr", addr,
			"error", err)
		return nil, fmt.Errorf("failed to connect to gRPC server: %v", err)
	}

	slog.Debug("gRPC connection established", "client_id", config.ClientID)

	// Create gRPC client
	client := NewTransportServiceClient(conn)

	// Set up metadata with client info and authentication
	md := metadata.New(map[string]string{
		"client-id": config.ClientID,
		"group-id":  config.GroupID,
		"username":  config.Username,
		"password":  config.Password,
	})

	// Create context with metadata
	streamCtx := metadata.NewOutgoingContext(context.Background(), md)

	// Create bidirectional stream
	stream, err := client.BiStream(streamCtx)
	if err != nil {
		conn.Close()
		slog.Error("Failed to create gRPC stream",
			"client_id", config.ClientID,
			"error", err)
		return nil, fmt.Errorf("failed to create gRPC stream: %v", err)
	}

	slog.Info("gRPC stream established successfully",
		"client_id", config.ClientID)

	// Create and return connection wrapper
	grpcConn := newGRPCConnection(stream, conn, config.ClientID, config.GroupID)
	return grpcConn, nil
}
