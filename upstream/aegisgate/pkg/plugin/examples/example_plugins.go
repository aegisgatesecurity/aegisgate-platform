// Package examples contains example plugin implementations for AegisGate.
package examples

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/plugin"
)

// ExampleFilterPlugin is a simple filter plugin that logs requests and responses.
// This demonstrates how to implement a filter plugin.
type ExampleFilterPlugin struct {
	logger     *slog.Logger
	config     plugin.PluginConfig
	stats      *FilterStats
	requestLog chan string
}

// FilterStats tracks filter statistics
type FilterStats struct {
	RequestsProcessed  int64
	ResponsesProcessed int64
	Errors             int64
}

// NewExampleFilterPlugin creates a new example filter plugin
func NewExampleFilterPlugin() *ExampleFilterPlugin {
	return &ExampleFilterPlugin{
		logger:     slog.Default(),
		stats:      &FilterStats{},
		requestLog: make(chan string, 100),
	}
}

// Metadata returns the plugin metadata
func (p *ExampleFilterPlugin) Metadata() plugin.PluginMetadata {
	return plugin.PluginMetadata{
		ID:           "example-filter",
		Name:         "Example Filter Plugin",
		Version:      "1.0.0",
		Description:  "An example filter plugin that logs requests and responses",
		Author:       "AegisGate Team",
		Website:      "https://aegisgatesecurity.io",
		Type:         plugin.TypeFilter,
		Tags:         []string{"example", "logging", "filter"},
		Capabilities: []string{"request-logging", "response-logging"},
	}
}

// Init initializes the plugin
func (p *ExampleFilterPlugin) Init(ctx context.Context, config plugin.PluginConfig) error {
	p.config = config
	p.logger.Info("ExampleFilterPlugin initialized", "config", config.Settings)
	return nil
}

// Start starts the plugin
func (p *ExampleFilterPlugin) Start(ctx context.Context) error {
	p.logger.Info("ExampleFilterPlugin started")

	// Start a background goroutine to process request logs
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-p.requestLog:
				p.logger.Debug("Request logged", "request", req)
			}
		}
	}()

	return nil
}

// Stop stops the plugin
func (p *ExampleFilterPlugin) Stop(ctx context.Context) error {
	p.logger.Info("ExampleFilterPlugin stopped",
		"requests", p.stats.RequestsProcessed,
		"responses", p.stats.ResponsesProcessed,
		"errors", p.stats.Errors)
	close(p.requestLog)
	return nil
}

// Hooks returns the hooks this plugin implements
func (p *ExampleFilterPlugin) Hooks() []plugin.HookType {
	return []plugin.HookType{
		plugin.HookRequestReceived,
		plugin.HookResponseSent,
		plugin.HookError,
	}
}

// ProcessRequest handles the request received hook
func (p *ExampleFilterPlugin) ProcessRequest(ctx context.Context, reqCtx *plugin.RequestContext) (*plugin.HookResult, error) {
	p.stats.RequestsProcessed++

	// Log request details
	select {
	case p.requestLog <- fmt.Sprintf("%s %s %s", reqCtx.Request.Method, reqCtx.Request.URL.Path, reqCtx.Protocol):
	default:
		// Channel full, skip logging
	}

	// Example: Add custom header
	reqCtx.Request.Header.Set("X-Example-Filter", "active")

	// Example: Store data in context for later hooks
	reqCtx.Metadata["example_filter_processed"] = time.Now()

	result := plugin.DefaultHookResult()
	return &result, nil
}

// ProcessResponse handles the response sent hook
func (p *ExampleFilterPlugin) ProcessResponse(ctx context.Context, reqCtx *plugin.RequestContext, respCtx *plugin.ResponseContext) (*plugin.HookResult, error) {
	p.stats.ResponsesProcessed++

	// Example: Add custom header to response
	if respCtx.Headers == nil {
		respCtx.Headers = make(http.Header)
	}
	respCtx.Headers.Set("X-Example-Filter-Processed", "true")

	result := plugin.DefaultHookResult()
	return &result, nil
}

// OnError handles errors (for ErrorHandler interface)
func (p *ExampleFilterPlugin) OnError(ctx context.Context, errCtx *plugin.ErrorContext) error {
	p.stats.Errors++
	p.logger.Error("ExampleFilterPlugin error",
		"hook", errCtx.Hook,
		"error", errCtx.Error,
		"connection_id", errCtx.ConnectionID)
	return nil
}

// GetStats returns the filter statistics
func (p *ExampleFilterPlugin) GetStats() *FilterStats {
	return p.stats
}

// Compile-time check that ExampleFilterPlugin implements required interfaces
var _ plugin.Plugin = (*ExampleFilterPlugin)(nil)
var _ plugin.RequestProcessor = (*ExampleFilterPlugin)(nil)
var _ plugin.ResponseProcessor = (*ExampleFilterPlugin)(nil)
var _ plugin.ErrorHandler = (*ExampleFilterPlugin)(nil)

// ExampleAnalyticsPlugin demonstrates an analytics plugin
type ExampleAnalyticsPlugin struct {
	logger  *slog.Logger
	config  plugin.PluginConfig
	metrics *AnalyticsMetrics
}

// AnalyticsMetrics holds analytics data
type AnalyticsMetrics struct {
	TotalRequests  int64
	TotalResponses int64
	TotalBytesIn   int64
	TotalBytesOut  int64
	AvgLatency     time.Duration
	TopPaths       map[string]int
	StatusCodes    map[int]int
}

// NewExampleAnalyticsPlugin creates a new analytics plugin
func NewExampleAnalyticsPlugin() *ExampleAnalyticsPlugin {
	return &ExampleAnalyticsPlugin{
		logger: slog.Default(),
		metrics: &AnalyticsMetrics{
			TopPaths:    make(map[string]int),
			StatusCodes: make(map[int]int),
		},
	}
}

// Metadata returns the plugin metadata
func (p *ExampleAnalyticsPlugin) Metadata() plugin.PluginMetadata {
	return plugin.PluginMetadata{
		ID:           "example-analytics",
		Name:         "Example Analytics Plugin",
		Version:      "1.0.0",
		Description:  "An example analytics plugin that tracks request metrics",
		Author:       "AegisGate Team",
		Type:         plugin.TypeAnalytics,
		Tags:         []string{"example", "analytics", "metrics"},
		Capabilities: []string{"analytics", "metrics"},
	}
}

// Init initializes the plugin
func (p *ExampleAnalyticsPlugin) Init(ctx context.Context, config plugin.PluginConfig) error {
	p.config = config
	p.logger.Info("ExampleAnalyticsPlugin initialized")
	return nil
}

// Start starts the plugin
func (p *ExampleAnalyticsPlugin) Start(ctx context.Context) error {
	p.logger.Info("ExampleAnalyticsPlugin started")
	return nil
}

// Stop stops the plugin
func (p *ExampleAnalyticsPlugin) Stop(ctx context.Context) error {
	p.logger.Info("ExampleAnalyticsPlugin stopped",
		"total_requests", p.metrics.TotalRequests,
		"total_responses", p.metrics.TotalResponses,
		"total_bytes_in", p.metrics.TotalBytesIn,
		"total_bytes_out", p.metrics.TotalBytesOut)
	return nil
}

// Hooks returns the hooks this plugin implements
func (p *ExampleAnalyticsPlugin) Hooks() []plugin.HookType {
	return []plugin.HookType{
		plugin.HookRequestReceived,
		plugin.HookAfterResponse,
	}
}

// ProcessRequest tracks request metrics
func (p *ExampleAnalyticsPlugin) ProcessRequest(ctx context.Context, reqCtx *plugin.RequestContext) (*plugin.HookResult, error) {
	p.metrics.TotalRequests++

	path := reqCtx.Request.URL.Path
	p.metrics.TopPaths[path]++

	if reqCtx.Request.ContentLength > 0 {
		p.metrics.TotalBytesIn += reqCtx.Request.ContentLength
	}

	result := plugin.DefaultHookResult()
	return &result, nil
}

// ProcessResponse tracks response metrics
func (p *ExampleAnalyticsPlugin) ProcessResponse(ctx context.Context, reqCtx *plugin.RequestContext, respCtx *plugin.ResponseContext) (*plugin.HookResult, error) {
	p.metrics.TotalResponses++

	statusCode := respCtx.StatusCode
	p.metrics.StatusCodes[statusCode]++

	if len(respCtx.Body) > 0 {
		p.metrics.TotalBytesOut += int64(len(respCtx.Body))
	}

	// Track latency
	p.metrics.AvgLatency = (p.metrics.AvgLatency + respCtx.Latency) / 2

	result := plugin.DefaultHookResult()
	return &result, nil
}

// GetMetrics returns the analytics metrics
func (p *ExampleAnalyticsPlugin) GetMetrics() *AnalyticsMetrics {
	return p.metrics
}

// Compile-time check
var _ plugin.Plugin = (*ExampleAnalyticsPlugin)(nil)
var _ plugin.RequestProcessor = (*ExampleAnalyticsPlugin)(nil)
var _ plugin.ResponseProcessor = (*ExampleAnalyticsPlugin)(nil)

// ExamplePeriodicPlugin demonstrates a plugin with periodic tasks
type ExamplePeriodicPlugin struct {
	logger      *slog.Logger
	config      plugin.PluginConfig
	taskCount   int
	lastRunTime time.Time
}

// NewExamplePeriodicPlugin creates a new periodic task plugin
func NewExamplePeriodicPlugin() *ExamplePeriodicPlugin {
	return &ExamplePeriodicPlugin{
		logger:    slog.Default(),
		taskCount: 0,
	}
}

// Metadata returns the plugin metadata
func (p *ExamplePeriodicPlugin) Metadata() plugin.PluginMetadata {
	return plugin.PluginMetadata{
		ID:           "example-periodic",
		Name:         "Example Periodic Plugin",
		Version:      "1.0.0",
		Description:  "An example plugin that performs periodic tasks",
		Author:       "AegisGate Team",
		Type:         plugin.TypeProcessor,
		Tags:         []string{"example", "periodic", "maintenance"},
		Capabilities: []string{"maintenance", "cleanup"},
	}
}

// Init initializes the plugin
func (p *ExamplePeriodicPlugin) Init(ctx context.Context, config plugin.PluginConfig) error {
	p.config = config
	p.logger.Info("ExamplePeriodicPlugin initialized")
	return nil
}

// Start starts the plugin
func (p *ExamplePeriodicPlugin) Start(ctx context.Context) error {
	p.logger.Info("ExamplePeriodicPlugin started")
	return nil
}

// Stop stops the plugin
func (p *ExamplePeriodicPlugin) Stop(ctx context.Context) error {
	p.logger.Info("ExamplePeriodicPlugin stopped", "total_tasks", p.taskCount)
	return nil
}

// Hooks returns the hooks this plugin implements
func (p *ExamplePeriodicPlugin) Hooks() []plugin.HookType {
	return []plugin.HookType{
		plugin.HookPeriodic,
	}
}

// OnPeriodic runs the periodic task
func (p *ExamplePeriodicPlugin) OnPeriodic(ctx context.Context, periodicCtx *plugin.PeriodicContext) error {
	p.taskCount++
	p.lastRunTime = periodicCtx.Timestamp

	p.logger.Info("Periodic task executed",
		"task_number", p.taskCount,
		"timestamp", periodicCtx.Timestamp,
		"interval", periodicCtx.Interval)

	// Example: Perform cleanup, health checks, etc.

	return nil
}

// Interval returns the interval for periodic tasks
func (p *ExamplePeriodicPlugin) Interval() time.Duration {
	return 1 * time.Minute
}

// GetTaskCount returns the number of tasks executed
func (p *ExamplePeriodicPlugin) GetTaskCount() int {
	return p.taskCount
}

// Compile-time check
var _ plugin.Plugin = (*ExamplePeriodicPlugin)(nil)
var _ plugin.PeriodicTask = (*ExamplePeriodicPlugin)(nil)
