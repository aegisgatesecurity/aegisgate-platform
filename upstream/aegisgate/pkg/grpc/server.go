// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// NewServer creates a new gRPC server
func NewServer(port string, _ *slog.Logger) *grpc.Server {
	// Configure server options
	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(100),
		grpc.MaxRecvMsgSize(1024 * 1024 * 10), // 10MB
		grpc.ConnectionTimeout(30 * time.Second),
	}

	// Create server
	s := grpc.NewServer(opts...)

	return s
}

// Start starts the gRPC server on the given port
func Start(port string, logger *slog.Logger) (*grpc.Server, error) {
	if logger == nil {
		logger = slog.Default()
	}

	lis, err := net.Listen("tcp", port)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", port, err)
	}

	logger.Info("Starting gRPC server", "port", port)

	s := grpc.NewServer()

	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Error("gRPC server error", "error", err)
		}
	}()

	return s, nil
}

// Stop gracefully stops the gRPC server
func Stop(s *grpc.Server) {
	if s != nil {
		s.GracefulStop()
	}
}

// UnaryInterceptor returns a unary server interceptor for logging
func UnaryInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		logger.Info("gRPC request", "method", info.FullMethod)

		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			logger.Debug("Metadata", "md", md)
		}

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		if err != nil {
			logger.Error("gRPC error", "method", info.FullMethod, "error", err, "duration", duration)
		} else {
			logger.Info("gRPC response", "method", info.FullMethod, "duration", duration)
		}

		return resp, err
	}
}

// StreamInterceptor returns a stream server interceptor for logging
func StreamInterceptor(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		logger.Info("gRPC stream", "method", info.FullMethod)
		err := handler(srv, ss)
		if err != nil {
			logger.Error("gRPC stream error", "method", info.FullMethod, "error", err)
		} else {
			logger.Info("gRPC stream completed", "method", info.FullMethod)
		}
		return err
	}
}

// RunServer runs the gRPC server with proper lifecycle management
func RunServer(port string, logger *slog.Logger) error {
	server, err := Start(port, logger)
	if err != nil {
		return err
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	Stop(server)
	slog.Default().Info("gRPC server stopped")
	return nil
}
