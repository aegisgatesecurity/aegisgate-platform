// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
)

// ProxyService implements the Proxy service
type ProxyService struct {
	UnimplementedProxyServiceServer
	server *proxy.Proxy
	logger *slog.Logger
}

// NewProxyService creates a new proxy service
func NewProxyService(server *proxy.Proxy, logger *slog.Logger) *ProxyService {
	return &ProxyService{
		server: server,
		logger: logger,
	}
}

// GetStats returns proxy statistics
func (s *ProxyService) GetStats(ctx context.Context, req *GetProxyStatsRequest) (*GetProxyStatsResponse, error) {
	stats := s.server.GetStatsStruct()

	return &GetProxyStatsResponse{
		RequestsTotal:     stats.RequestsTotal,
		RequestsBlocked:   stats.RequestsBlocked,
		RequestsAllowed:   stats.RequestsAllowed,
		BytesIn:           stats.BytesIn,
		BytesOut:          stats.BytesOut,
		ActiveConnections: int32(stats.ActiveConnections),
		AvgLatencyMs:      stats.AvgLatencyMs,
		P99LatencyMs:      stats.P99LatencyMs,
		Errors:            stats.Errors,
	}, nil
}

// GetHealth returns proxy health status
func (s *ProxyService) GetHealth(ctx context.Context, req *GetProxyHealthRequest) (*GetProxyHealthResponse, error) {
	return &GetProxyHealthResponse{
		Status:      "healthy",
		Uptime:      0,
		MemoryUsage: 0,
		Goroutines:  0,
	}, nil
}

// GetConfig returns proxy configuration
func (s *ProxyService) GetConfig(ctx context.Context, req *GetProxyConfigRequest) (*GetProxyConfigResponse, error) {
	return &GetProxyConfigResponse{
		Enabled:        true,
		Host:           "0.0.0.0",
		Port:           8080,
		TlsEnabled:     false,
		RateLimit:      100,
		RateLimitBurst: 100,
		CorsEnabled:    false,
		CorsOrigins:    []string{},
	}, nil
}

// IsEnabled checks if proxy is enabled
func (s *ProxyService) IsEnabled(ctx context.Context, req *IsProxyEnabledRequest) (*IsProxyEnabledResponse, error) {
	return &IsProxyEnabledResponse{Enabled: s.server.IsEnabled()}, nil
}

// Enable enables the proxy
func (s *ProxyService) Enable(ctx context.Context, req *EnableProxyRequest) (*EnableProxyResponse, error) {
	return &EnableProxyResponse{Success: false, Error: "Use HTTP server to start proxy"}, nil
}

// Disable disables the proxy
func (s *ProxyService) Disable(ctx context.Context, req *DisableProxyRequest) (*DisableProxyResponse, error) {
	return &DisableProxyResponse{Success: false}, nil
}

// GetViolations returns proxy violations (placeholder)
func (s *ProxyService) GetViolations(ctx context.Context, req *GetViolationsRequest) (*GetViolationsResponse, error) {
	return &GetViolationsResponse{Violations: []*Violation{}}, nil
}

// ClearViolations clears proxy violations (placeholder)
func (s *ProxyService) ClearViolations(ctx context.Context, req *ClearViolationsRequest) (*ClearViolationsResponse, error) {
	return &ClearViolationsResponse{Success: true}, nil
}
