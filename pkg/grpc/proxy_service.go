// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Proxy Service Implementation
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ProxyService implements ProxyServiceServer using a ProxyBackend.
type ProxyService struct {
	UnimplementedProxyServiceServer
	backend ProxyBackend
	logger  *slog.Logger
}

// NewProxyService creates a new ProxyService with the given backend.
func NewProxyService(backend ProxyBackend, logger *slog.Logger) *ProxyService {
	return &ProxyService{backend: backend, logger: logger}
}

// GetStats returns proxy statistics.
func (s *ProxyService) GetStats(ctx context.Context, req *GetProxyStatsRequest) (*GetProxyStatsResponse, error) {
	stats, err := s.backend.GetStats(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get proxy stats: %v", err)
	}

	return &GetProxyStatsResponse{
		RequestsTotal:     stats.RequestsTotal,
		RequestsBlocked:   stats.RequestsBlocked,
		RequestsAllowed:   stats.RequestsAllowed,
		BytesIn:           stats.BytesIn,
		BytesOut:          stats.BytesOut,
		ActiveConnections: int32(stats.ActiveConnections), //nosec G115 -- bounded by protobuf int32 range
		AvgLatencyMs:      stats.AvgLatencyMs,
		P99LatencyMs:      stats.P99LatencyMs,
		Errors:            stats.Errors,
	}, nil
}

// GetHealth returns proxy health status.
func (s *ProxyService) GetHealth(ctx context.Context, req *GetProxyHealthRequest) (*GetProxyHealthResponse, error) {
	health, err := s.backend.GetHealth(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get proxy health: %v", err)
	}

	return &GetProxyHealthResponse{
		Status:      health.Status,
		Uptime:      health.Uptime,
		MemoryUsage: health.MemoryUsage,
		Goroutines:  health.Goroutines,
	}, nil
}

// GetConfig returns proxy configuration.
func (s *ProxyService) GetConfig(ctx context.Context, req *GetProxyConfigRequest) (*GetProxyConfigResponse, error) {
	cfg, err := s.backend.GetConfig(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get proxy config: %v", err)
	}

	return &GetProxyConfigResponse{
		Enabled:        cfg.Enabled,
		Host:           cfg.Host,
		Port:           int32(cfg.Port), //nosec G115 -- port bounded to 0-65535
		TlsEnabled:     cfg.TLSEnabled,
		RateLimit:      cfg.RateLimit,
		RateLimitBurst: cfg.RateLimitBurst,
		CorsEnabled:    cfg.CORSEnabled,
		CorsOrigins:    cfg.CORSOrigins,
	}, nil
}

// IsEnabled checks if the proxy is enabled.
func (s *ProxyService) IsEnabled(ctx context.Context, req *IsProxyEnabledRequest) (*IsProxyEnabledResponse, error) {
	enabled, err := s.backend.IsEnabled(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check proxy status: %v", err)
	}
	return &IsProxyEnabledResponse{Enabled: enabled}, nil
}

// Enable enables the proxy.
func (s *ProxyService) Enable(ctx context.Context, req *EnableProxyRequest) (*EnableProxyResponse, error) {
	if err := s.backend.Enable(ctx); err != nil {
		return &EnableProxyResponse{Success: false, Error: err.Error()}, nil
	}
	return &EnableProxyResponse{Success: true}, nil
}

// Disable disables the proxy.
func (s *ProxyService) Disable(ctx context.Context, req *DisableProxyRequest) (*DisableProxyResponse, error) {
	if err := s.backend.Disable(ctx); err != nil {
		return &DisableProxyResponse{Success: false}, nil
	}
	return &DisableProxyResponse{Success: true}, nil
}

// GetViolations returns proxy violations.
func (s *ProxyService) GetViolations(ctx context.Context, req *GetViolationsRequest) (*GetViolationsResponse, error) {
	violations, err := s.backend.GetViolations(ctx, req.Severities, req.Limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get violations: %v", err)
	}

	result := make([]*Violation, 0, len(violations))
	for _, v := range violations {
		result = append(result, &Violation{
			Id:        v.ID,
			Type:      v.Type,
			Severity:  v.Severity,
			Message:   v.Message,
			ClientIp:  v.ClientIP,
			Method:    v.Method,
			Path:      v.Path,
			Blocked:   v.Blocked,
			Timestamp: v.Timestamp,
		})
	}

	return &GetViolationsResponse{Violations: result}, nil
}

// ClearViolations clears all proxy violations.
func (s *ProxyService) ClearViolations(ctx context.Context, req *ClearViolationsRequest) (*ClearViolationsResponse, error) {
	if err := s.backend.ClearViolations(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to clear violations: %v", err)
	}
	return &ClearViolationsResponse{Success: true}, nil
}
