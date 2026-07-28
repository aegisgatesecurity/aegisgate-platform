// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Core Service Implementation
// =========================================================================

package grpc

import (
	"context"
	"log/slog"

	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CoreService implements CoreServiceServer using a MetricsBackend.
type CoreService struct {
	UnimplementedCoreServiceServer
	backend   MetricsBackend
	logger    *slog.Logger
	startTime time.Time
}

// NewCoreService creates a new CoreService with the given backend.
func NewCoreService(backend MetricsBackend, logger *slog.Logger) *CoreService {
	return &CoreService{
		backend:   backend,
		logger:    logger,
		startTime: time.Now(),
	}
}

// ListModules lists all registered modules.
func (s *CoreService) ListModules(ctx context.Context, req *ListModulesRequest) (*ListModulesResponse, error) {
	// Module registry is not a backend concern; return platform modules statically.
	modules := []*ModuleInfo{
		{Id: "proxy", Name: "Proxy", Version: Version, Description: "AI API security proxy", Category: "security", Status: ModuleStatusRunning},
		{Id: "auth", Name: "Auth", Version: Version, Description: "Authentication and session management", Category: "identity", Status: ModuleStatusRunning},
		{Id: "compliance", Name: "Compliance", Version: Version, Description: "Compliance framework checking", Category: "governance", Status: ModuleStatusRunning},
		{Id: "siem", Name: "SIEM", Version: Version, Description: "Security event management", Category: "monitoring", Status: ModuleStatusRunning},
		{Id: "mcp", Name: "MCP Server", Version: Version, Description: "Model Context Protocol gateway", Category: "integration", Status: ModuleStatusRunning},
		{Id: "scanner", Name: "Scanner", Version: Version, Description: "Content pattern scanner", Category: "security", Status: ModuleStatusRunning},
		{Id: "tls", Name: "TLS", Version: Version, Description: "TLS/mTLS certificate management", Category: "security", Status: ModuleStatusRunning},
	}
	return &ListModulesResponse{Modules: modules}, nil
}

// GetModule gets a module by ID.
func (s *CoreService) GetModule(ctx context.Context, req *GetModuleRequest) (*GetModuleResponse, error) {
	if req.ModuleId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "module_id is required")
	}

	// Look up from the static module list.
	modules := []*ModuleInfo{
		{Id: "proxy", Name: "Proxy", Version: Version, Description: "AI API security proxy", Category: "security", Status: ModuleStatusRunning},
		{Id: "auth", Name: "Auth", Version: Version, Description: "Authentication and session management", Category: "identity", Status: ModuleStatusRunning},
		{Id: "compliance", Name: "Compliance", Version: Version, Description: "Compliance framework checking", Category: "governance", Status: ModuleStatusRunning},
		{Id: "siem", Name: "SIEM", Version: Version, Description: "Security event management", Category: "monitoring", Status: ModuleStatusRunning},
		{Id: "mcp", Name: "MCP Server", Version: Version, Description: "Model Context Protocol gateway", Category: "integration", Status: ModuleStatusRunning},
		{Id: "scanner", Name: "Scanner", Version: Version, Description: "Content pattern scanner", Category: "security", Status: ModuleStatusRunning},
		{Id: "tls", Name: "TLS", Version: Version, Description: "TLS/mTLS certificate management", Category: "security", Status: ModuleStatusRunning},
	}

	for _, m := range modules {
		if m.Id == req.ModuleId {
			return &GetModuleResponse{Module: m}, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "module not found: %s", req.ModuleId)
}

// GetHealth returns platform health status.
func (s *CoreService) GetHealth(ctx context.Context, req *GetHealthRequest) (*GetHealthResponse, error) {
	health, err := s.backend.GetHealth(ctx)
	if err != nil {
		// Fallback to basic health if backend is unavailable.
		return &GetHealthResponse{
			Status: "degraded",
			Checks: []*HealthCheck{
				{Name: "system", Status: "degraded", Message: "metrics backend unavailable"},
			},
		}, nil
	}

	checks := make([]*HealthCheck, 0, len(health.Checks))
	for _, c := range health.Checks {
		checks = append(checks, &HealthCheck{
			Name:    c.Name,
			Status:  c.Status,
			Message: c.Message,
		})
	}

	return &GetHealthResponse{
		Status: health.Status,
		Checks: checks,
	}, nil
}

// GetMetrics returns system metrics.
func (s *CoreService) GetMetrics(ctx context.Context, req *GetMetricsRequest) (*GetMetricsResponse, error) {
	stats, err := s.backend.GetStats(ctx)
	if err != nil {
		// Fallback to runtime-based metrics if backend is unavailable.
		return &GetMetricsResponse{
			TotalRequests:     0,
			BlockedRequests:   0,
			ActiveUsers:       0,
			ActiveConnections: 0,
			Uptime:            time.Since(s.startTime).Seconds(),
		}, nil
	}

	return &GetMetricsResponse{
		TotalRequests:     stats.TotalRequests,
		BlockedRequests:   stats.BlockedRequests,
		ActiveUsers:       int32(stats.ActiveUsers),
		ActiveConnections: int32(stats.ActiveConnections),
		Uptime:            stats.Uptime,
	}, nil
}

// GetVersion returns version information.
func (s *CoreService) GetVersion(ctx context.Context, req *GetVersionRequest) (*GetVersionResponse, error) {
	return &GetVersionResponse{
		Version:   Version,
		BuildTime: BuildTime,
		GitCommit: GitCommit,
	}, nil
}

// GetUptime returns system uptime.
func (s *CoreService) GetUptime(ctx context.Context, req *GetUptimeRequest) (*GetUptimeResponse, error) {
	uptime, err := s.backend.GetUptime(ctx)
	if err != nil {
		// Fallback to local uptime calculation.
		uptime = time.Since(s.startTime).Seconds()
	}

	return &GetUptimeResponse{Uptime: uptime}, nil
}

// GetRegistryStatus returns module registry status.
func (s *CoreService) GetRegistryStatus(ctx context.Context, req *GetRegistryStatusRequest) (*GetRegistryStatusResponse, error) {
	// Count modules from the static list.
	total := 7
	return &GetRegistryStatusResponse{
		TotalModules:     int32(total),
		ActiveModules:    int32(total),
		HealthyModules:   int32(total),
		UnhealthyModules: 0,
	}, nil
}

// EnableModule enables a module.
func (s *CoreService) EnableModule(ctx context.Context, req *EnableModuleRequest) (*EnableModuleResponse, error) {
	if req.ModuleId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "module_id is required")
	}
	// Module enablement is managed by the platform config; gRPC is read-only.
	return &EnableModuleResponse{Success: false}, nil
}

// DisableModule disables a module.
func (s *CoreService) DisableModule(ctx context.Context, req *DisableModuleRequest) (*DisableModuleResponse, error) {
	if req.ModuleId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "module_id is required")
	}
	// Module disablement is managed by the platform config; gRPC is read-only.
	return &DisableModuleResponse{Success: false}, nil
}

// Runtime metrics available via health/metrics backends.