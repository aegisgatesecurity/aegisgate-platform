// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Server Lifecycle
// =========================================================================
//
// Provides gRPC server creation, lifecycle management, and interceptors.
// All seven platform services (Auth, Proxy, Compliance, SIEM, Webhook,
// Core, TLS) are registered in NewGRPCServer().
//
// Wire into cmd/aegisgate-platform:
//
//	server, err := grpc.NewGRPCServer(deps, logger)
//	if err != nil { log.Fatal(err) }
//	go server.Serve(":50051")
//	// ... shutdown:
//	server.GracefulStop()
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
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
)

// Dependencies holds all external dependencies required by gRPC services.
// All fields are optional — services that receive a nil dependency
// return codes.Unimplemented for their RPCs.
type Dependencies struct {
	Auth       AuthBackend
	Compliance ComplianceBackend
	Proxy      ProxyBackend
	SIEM       SIEMBackend
	Webhook    WebhookBackend
	Metrics    MetricsBackend
	TLS        TLSBackend
}

// NewGRPCServer creates a fully configured gRPC server with all seven
// platform services registered, health checking enabled, and server
// reflection enabled for tools like grpcurl.
//
// Dependencies may be partially nil — missing backends result in
// Unimplemented responses for that service's RPCs.
func NewGRPCServer(deps Dependencies, logger *slog.Logger) (*grpc.Server, error) {
	if logger == nil {
		logger = slog.Default()
	}

	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(100),
		grpc.MaxRecvMsgSize(10 * 1024 * 1024), // 10MB
		grpc.ConnectionTimeout(30 * time.Second),
		grpc.ChainUnaryInterceptor(
			unaryRecoveryInterceptor(logger),
			unaryLoggingInterceptor(logger),
		),
		grpc.ChainStreamInterceptor(
			streamRecoveryInterceptor(logger),
			streamLoggingInterceptor(logger),
		),
	}

	server := grpc.NewServer(opts...)

	// Register all seven platform services.
	registerAllServices(server, deps, logger)

	// Enable gRPC health checking.
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(server, healthServer)
	// Mark all services as SERVING.
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(AuthService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(ProxyService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(ComplianceService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(SIEMService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(WebhookService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(CoreService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(TLSSvc_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable server reflection for grpcurl and other tools.
	reflection.Register(server)

	logger.Info("gRPC server created", "services", 7, "methods", MethodCount())
	return server, nil
}

// registerAllServices creates service implementations and registers them.
func registerAllServices(server *grpc.Server, deps Dependencies, logger *slog.Logger) {
	rh := &RegisterHelper{Server: server}

	// Auth service
	if deps.Auth != nil {
		rh.RegisterAuthService(NewAuthService(deps.Auth, logger))
	} else {
		rh.RegisterAuthService(&UnimplementedAuthServiceServer{})
	}

	// Proxy service
	if deps.Proxy != nil {
		rh.RegisterProxyService(NewProxyService(deps.Proxy, logger))
	} else {
		rh.RegisterProxyService(&UnimplementedProxyServiceServer{})
	}

	// Compliance service
	if deps.Compliance != nil {
		rh.RegisterComplianceService(NewComplianceService(deps.Compliance, logger))
	} else {
		rh.RegisterComplianceService(&UnimplementedComplianceServiceServer{})
	}

	// SIEM service
	if deps.SIEM != nil {
		rh.RegisterSIEMService(NewSIEMService(deps.SIEM, logger))
	} else {
		rh.RegisterSIEMService(&UnimplementedSIEMServiceServer{})
	}

	// Webhook service
	if deps.Webhook != nil {
		rh.RegisterWebhookService(NewWebhookService(deps.Webhook, logger))
	} else {
		rh.RegisterWebhookService(&UnimplementedWebhookServiceServer{})
	}

	// Core service
	if deps.Metrics != nil {
		rh.RegisterCoreService(NewCoreService(deps.Metrics, logger))
	} else {
		rh.RegisterCoreService(&UnimplementedCoreServiceServer{})
	}

	// TLS service
	if deps.TLS != nil {
		rh.RegisterTLSSvc(NewTLSSvc(deps.TLS, logger))
	} else {
		rh.RegisterTLSSvc(&UnimplementedTLSSvcServer{})
	}
}

// Serve starts the gRPC server on the given address (e.g. ":50051").
// Blocks until the server stops. Returns the listener error.
func Serve(server *grpc.Server, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc: listen %s: %w", addr, err)
	}
	return server.Serve(lis)
}

// GracefulStop gracefully stops the gRPC server with a timeout.
// If the server doesn't stop within the timeout, it calls Stop().
func GracefulStop(server *grpc.Server, timeout time.Duration) {
	if server == nil {
		return
	}

	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		// Graceful stop completed.
	case <-time.After(timeout):
		// Timeout — force stop.
		server.Stop()
	}
}

// RunServer is a convenience function that creates, serves, and manages
// the gRPC server lifecycle with signal handling. Intended for main().
func RunServer(addr string, deps Dependencies, logger *slog.Logger) error {
	server, err := NewGRPCServer(deps, logger)
	if err != nil {
		return fmt.Errorf("grpc: create server: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := Serve(server, addr); err != nil {
			errCh <- err
		}
	}()

	logger.Info("gRPC server starting", "addr", addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		logger.Info("gRPC server shutting down")
		GracefulStop(server, 10*time.Second)
		return nil
	case err := <-errCh:
		return fmt.Errorf("grpc: serve: %w", err)
	}
}

// ====================================================================
// Interceptors
// ====================================================================

// unaryLoggingInterceptor logs every unary RPC call.
func unaryLoggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		method := info.FullMethod

		logger.Debug("gRPC unary request", "method", method)

		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if ua := md.Get("user-agent"); len(ua) > 0 {
				logger.Debug("gRPC client", "method", method, "user-agent", ua[0])
			}
		}

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		if err != nil {
			logger.Error("gRPC unary error", "method", method, "error", err, "duration", duration)
		} else {
			logger.Info("gRPC unary response", "method", method, "duration", duration)
		}

		return resp, err
	}
}

// streamLoggingInterceptor logs every streaming RPC call.
func streamLoggingInterceptor(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		logger.Info("gRPC stream started", "method", info.FullMethod, "client_stream", info.IsClientStream, "server_stream", info.IsServerStream)
		start := time.Now()

		err := handler(srv, ss)

		duration := time.Since(start)
		if err != nil {
			logger.Error("gRPC stream error", "method", info.FullMethod, "error", err, "duration", duration)
		} else {
			logger.Info("gRPC stream completed", "method", info.FullMethod, "duration", duration)
		}

		return err
	}
}

// unaryRecoveryInterceptor recovers from panics in unary handlers.
func unaryRecoveryInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("gRPC panic recovered",
					"method", info.FullMethod,
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = fmt.Errorf("internal server error: %v", r)
			}
		}()
		return handler(ctx, req)
	}
}

// streamRecoveryInterceptor recovers from panics in stream handlers.
func streamRecoveryInterceptor(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("gRPC stream panic recovered",
					"method", info.FullMethod,
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = fmt.Errorf("internal server error: %v", r)
			}
		}()
		return handler(srv, ss)
	}
}

// ====================================================================
// Version info (set at build time via ldflags)
// ====================================================================

// Version is the platform version, overridden at build time.
var Version = "3.5.0"

// BuildTime is the build timestamp, overridden at build time.
var BuildTime = "unknown"

// GitCommit is the git commit hash, overridden at build time.
var GitCommit = "unknown"

// ParseHealthStatus normalizes a health status string.
func ParseHealthStatus(s string) grpc_health_v1.HealthCheckResponse_ServingStatus {
	switch strings.ToLower(s) {
	case "healthy", "serving", "ok", "up":
		return grpc_health_v1.HealthCheckResponse_SERVING
	case "degraded", "warning":
		return grpc_health_v1.HealthCheckResponse_SERVING
	case "unhealthy", "down", "error":
		return grpc_health_v1.HealthCheckResponse_NOT_SERVING
	default:
		return grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN
	}
}
