// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package grpc

import (
	"context"
	"log/slog"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/metrics"
)

// CoreService implements the Core service
type CoreService struct {
	UnimplementedCoreServiceServer
	metrics   *metrics.Manager
	logger    *slog.Logger
	startTime time.Time
}

// NewCoreService creates a new core service
func NewCoreService(metrics *metrics.Manager, logger *slog.Logger) *CoreService {
	return &CoreService{
		metrics:   metrics,
		logger:    logger,
		startTime: time.Now(),
	}
}

// ListModules lists all registered modules
func (s *CoreService) ListModules(ctx context.Context, req *ListModulesRequest) (*ListModulesResponse, error) {
	// Simplified - return empty list
	return &ListModulesResponse{Modules: []*ModuleInfo{}}, nil
}

// GetModule gets a module by ID
func (s *CoreService) GetModule(ctx context.Context, req *GetModuleRequest) (*GetModuleResponse, error) {
	return nil, nil
}

// GetHealth returns health status
func (s *CoreService) GetHealth(ctx context.Context, req *GetHealthRequest) (*GetHealthResponse, error) {
	health := s.metrics.GetHealth()
	return &GetHealthResponse{
		Status: health["status"].(string),
		Checks: []*HealthCheck{
			{Name: "system", Status: "healthy", Message: "System operational"},
		},
	}, nil
}

// GetMetrics returns system metrics
func (s *CoreService) GetMetrics(ctx context.Context, req *GetMetricsRequest) (*GetMetricsResponse, error) {
	stats := s.metrics.GetStats()
	return &GetMetricsResponse{
		TotalRequests:     stats["total_requests"].(int64),
		BlockedRequests:   stats["blocked_requests"].(int64),
		ActiveUsers:       int32(stats["active_users"].(int64)),
		ActiveConnections: int32(stats["active_connections"].(int64)),
		Uptime:            stats["uptime"].(float64),
	}, nil
}

// GetVersion returns version info
func (s *CoreService) GetVersion(ctx context.Context, req *GetVersionRequest) (*GetVersionResponse, error) {
	return &GetVersionResponse{
		Version:   "0.36.0",
		BuildTime: "unknown",
		GitCommit: "unknown",
	}, nil
}

// GetUptime returns system uptime
func (s *CoreService) GetUptime(ctx context.Context, req *GetUptimeRequest) (*GetUptimeResponse, error) {
	return &GetUptimeResponse{
		Uptime: s.metrics.GetUptime(),
	}, nil
}

// GetRegistryStatus returns registry status
func (s *CoreService) GetRegistryStatus(ctx context.Context, req *GetRegistryStatusRequest) (*GetRegistryStatusResponse, error) {
	return &GetRegistryStatusResponse{
		TotalModules:     0,
		ActiveModules:    0,
		HealthyModules:   0,
		UnhealthyModules: 0,
	}, nil
}

// EnableModule enables a module
func (s *CoreService) EnableModule(ctx context.Context, req *EnableModuleRequest) (*EnableModuleResponse, error) {
	return &EnableModuleResponse{Success: false}, nil
}

// DisableModule disables a module
func (s *CoreService) DisableModule(ctx context.Context, req *DisableModuleRequest) (*DisableModuleResponse, error) {
	return &DisableModuleResponse{Success: false}, nil
}
