// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform Go SDK — gRPC Client (v4.3.1)
// =========================================================================
//
// grpc_client.go provides a gRPC client connector for the AegisGate
// gRPC server. The gRPC API exposes seven services: Auth, Proxy,
// Compliance, SIEM, Webhook, Core, and TLS.
//
// For the v4.3.0+ pipelines (DSAR, Legal Hold, A/B Testing), use the HTTP
// client (client.go). These pipelines do not yet have gRPC service
// descriptors. Future versions may add gRPC bindings for them.
//
// Basic usage:
//
//	cfg := aegisgate.NewConfig(
//	    aegisgate.WithBaseURL("aegisgate.example.com:50051"),
//	    aegisgate.WithToken("your-token"),
//	)
//	grpcClient, err := aegisgate.NewGRPCClient(cfg)
//	if err != nil { log.Fatal(err) }
//	defer grpcClient.Close()
//
//	ctx := context.Background()
//	resp, err := grpcClient.Auth.ValidateToken(ctx, &aegisgate.ValidateTokenRequest{
//	    Token: "session-token",
//	})
// =========================================================================

package aegisgate

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// GRPCClient is the gRPC client for the AegisGate platform server.
// It connects to the gRPC server and provides typed access to the
// seven registered gRPC services.
//
// For DSAR, Legal Hold, and A/B Testing endpoints, use the HTTP
// client (Client) instead — these pipelines are HTTP-only in v4.3.x.
type GRPCClient struct {
	conn   *grpc.ClientConn
	cfg    *Config
	once   sync.Once
	closed bool

	// gRPC service stubs are populated lazily on first use.
	// The gRPC server uses hand-crafted service descriptors, so
	// we use raw grpc.ServiceDesc-based invocations rather than
	// generated stubs.
}

// NewGRPCClient creates a gRPC client from the provided configuration.
// The BaseURL should be in "host:port" format (e.g., "localhost:50051").
//
// If cfg.TLSConfig is non-nil, TLS credentials are used. Otherwise,
// insecure credentials are used (for local development only).
func NewGRPCClient(cfg *Config) (*GRPCClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("aegisgate: config must not be nil")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("aegisgate: BaseURL (host:port) is required")
	}

	var creds credentials.TransportCredentials
	if cfg.TLSConfig != nil {
		creds = credentials.NewTLS(cfg.TLSConfig)
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(cfg.BaseURL,
		grpc.WithTransportCredentials(creds),
		grpc.WithUnaryInterceptor(grpcAuthInterceptor(cfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("aegisgate gRPC: failed to connect to %s: %w", cfg.BaseURL, err)
	}

	return &GRPCClient{
		conn: conn,
		cfg:  cfg,
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *GRPCClient) Close() error {
	c.closed = true
	return c.conn.Close()
}

// Conn returns the underlying gRPC client connection for advanced use
// cases (e.g., calling services via raw method invocation or reflection).
func (c *GRPCClient) Conn() *grpc.ClientConn {
	return c.conn
}

// Context returns a context with authentication metadata attached,
// suitable for passing to gRPC method calls. If both Token and APIKey
// are configured, Token takes precedence.
func (c *GRPCClient) Context(ctx context.Context) context.Context {
	md := metadata.Pairs("user-agent", "aegisgate-go-sdk-grpc/"+Version)
	if c.cfg.Token != "" {
		md.Append("authorization", "Bearer "+c.cfg.Token)
	} else if c.cfg.APIKey != "" {
		md.Append("x-api-key", c.cfg.APIKey)
	}
	return metadata.NewOutgoingContext(ctx, md)
}

// grpcAuthInterceptor returns a unary client interceptor that attaches
// authentication headers to every gRPC call.
func grpcAuthInterceptor(cfg *Config) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// Attach auth metadata
		md := metadata.Pairs("user-agent", "aegisgate-go-sdk-grpc/"+Version)
		if cfg.Token != "" {
			md.Append("authorization", "Bearer "+cfg.Token)
		} else if cfg.APIKey != "" {
			md.Append("x-api-key", cfg.APIKey)
		}
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
