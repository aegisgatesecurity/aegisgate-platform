// Package healthcheck provides health monitoring for AegisGuard components
package healthcheck

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Status represents the health status of a component
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
	StatusUnknown   Status = "unknown"
)

// Component represents a health-checkable component
type Component interface {
	// Name returns the component name
	Name() string
	// Check performs the health check and returns status and details
	Check(ctx context.Context) *ComponentHealth
}

// ComponentHealth represents the health status of a component
type ComponentHealth struct {
	Name        string                 `json:"name"`
	Status      Status                 `json:"status"`
	Details     string                 `json:"details,omitempty"`
	Latency     time.Duration          `json:"latency,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
}

// Report represents a complete health check report
type Report struct {
	Status     string            `json:"status"`
	Timestamp  time.Time         `json:"timestamp"`
	Uptime     time.Duration     `json:"uptime"`
	Components []ComponentHealth `json:"components"`
	Summary    *Summary          `json:"summary,omitempty"`
}

// Summary provides a summary of the health check
type Summary struct {
	Total     int `json:"total"`
	Healthy   int `json:"healthy"`
	Degraded  int `json:"degraded"`
	Unhealthy int `json:"unhealthy"`
	Unknown   int `json:"unknown"`
}

// CheckAll checks all registered components
func CheckAll(ctx context.Context, components []Component) *Report {
	results := make([]ComponentHealth, 0, len(components))
	summary := &Summary{}

	for _, comp := range components {
		health := comp.Check(ctx)
		results = append(results, *health)

		switch health.Status {
		case StatusHealthy:
			summary.Healthy++
		case StatusDegraded:
			summary.Degraded++
		case StatusUnhealthy:
			summary.Unhealthy++
		default:
			summary.Unknown++
		}
		summary.Total++
	}

	// Determine overall status
	status := StatusHealthy
	if summary.Unhealthy > 0 {
		status = StatusUnhealthy
	} else if summary.Degraded > 0 {
		status = StatusDegraded
	} else if summary.Unknown > 0 && summary.Healthy == 0 {
		status = StatusUnknown
	}

	return &Report{
		Status:     string(status),
		Timestamp:  time.Now(),
		Components: results,
		Summary:    summary,
	}
}

// IsHealthy returns true if all components are healthy
func (r *Report) IsHealthy() bool {
	return r.Status == string(StatusHealthy)
}

// HasIssues returns true if any component has issues
func (r *Report) HasIssues() bool {
	return r.Status != string(StatusHealthy)
}

// GetComponent returns a component by name
func (r *Report) GetComponent(name string) *ComponentHealth {
	for i := range r.Components {
		if r.Components[i].Name == name {
			return &r.Components[i]
		}
	}
	return nil
}

// ============================================================================
// BASE COMPONENT
// ============================================================================

// BaseComponent provides common health check functionality
type BaseComponent struct {
	name    string
	checkFn func(ctx context.Context) *ComponentHealth
}

func (b *BaseComponent) Name() string {
	return b.name
}

func (b *BaseComponent) Check(ctx context.Context) *ComponentHealth {
	return b.checkFn(ctx)
}

// NewComponent creates a new health check component
func NewComponent(name string, checkFn func(ctx context.Context) *ComponentHealth) Component {
	return &BaseComponent{name: name, checkFn: checkFn}
}

// ============================================================================
// COMPOSITE CHECKER
// ============================================================================

// Checker manages multiple health check components
type Checker struct {
	components map[string]Component
	mu         sync.RWMutex
	startTime  time.Time
}

// NewChecker creates a new health checker
func NewChecker() *Checker {
	return &Checker{
		components: make(map[string]Component),
		startTime:  time.Now(),
	}
}

// Register adds a component to the health checker
func (c *Checker) Register(component Component) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.components[component.Name()] = component
}

// Unregister removes a component from the health checker
func (c *Checker) Unregister(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.components, name)
}

// Check performs health checks on all registered components
func (c *Checker) Check(ctx context.Context) *Report {
	c.mu.RLock()
	components := make([]Component, 0, len(c.components))
	for _, comp := range c.components {
		components = append(components, comp)
	}
	c.mu.RUnlock()

	report := CheckAll(ctx, components)
	report.Uptime = time.Since(c.startTime)
	return report
}

// CheckComponent checks a specific component by name
func (c *Checker) CheckComponent(ctx context.Context, name string) *ComponentHealth {
	c.mu.RLock()
	defer c.mu.RUnlock()

	comp, ok := c.components[name]
	if !ok {
		return &ComponentHealth{
			Name:        name,
			Status:      StatusUnknown,
			Error:       "component not found",
			LastChecked: time.Now(),
		}
	}

	return comp.Check(ctx)
}

// ListComponents returns all registered component names
func (c *Checker) ListComponents() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	names := make([]string, 0, len(c.components))
	for name := range c.components {
		names = append(names, name)
	}
	return names
}

// Uptime returns how long the checker has been running
func (c *Checker) Uptime() time.Duration {
	return time.Since(c.startTime)
}

// ============================================================================
// HTTP HANDLER
// ============================================================================

// Handler provides HTTP handlers for health endpoints
type Handler struct {
	checker *Checker
}

// NewHandler creates a new health handler
func NewHandler(checker *Checker) *Handler {
	return &Handler{checker: checker}
}

// HandleHealth returns a health check response for HTTP
func (h *Handler) HandleHealth(ctx context.Context) *Report {
	return h.checker.Check(ctx)
}

// HandleLiveness returns a simple liveness check (always OK if server is running)
func (h *Handler) HandleLiveness() *ComponentHealth {
	return &ComponentHealth{
		Name:        "liveness",
		Status:      StatusHealthy,
		Details:     "Server is alive",
		LastChecked: time.Now(),
	}
}

// HandleReadiness returns whether the server is ready to accept traffic
func (h *Handler) HandleReadiness(ctx context.Context) *ComponentHealth {
	report := h.checker.Check(ctx)

	// Server is ready if no critical components are unhealthy
	for _, comp := range report.Components {
		if comp.Status == StatusUnhealthy {
			return &ComponentHealth{
				Name:        "readiness",
				Status:      StatusUnhealthy,
				Details:     fmt.Sprintf("Unhealthy component: %s", comp.Name),
				Error:       comp.Error,
				LastChecked: time.Now(),
			}
		}
	}

	return &ComponentHealth{
		Name:        "readiness",
		Status:      StatusHealthy,
		Details:     "All components ready",
		LastChecked: time.Now(),
	}
}

// FormatReport formats the health report for different outputs
func FormatReport(report *Report, format string) (string, error) {
	switch format {
	case "json":
		return formatJSON(report)
	case "text", "plain":
		return formatText(report), nil
	case "summary":
		return formatSummary(report), nil
	default:
		return formatText(report), nil
	}
}

func formatJSON(report *Report) (string, error) {
	return fmt.Sprintf(`{
  "status": "%s",
  "timestamp": "%s",
  "uptime": "%s",
  "components": %s,
  "summary": {
    "total": %d,
    "healthy": %d,
    "degraded": %d,
    "unhealthy": %d
  }
}`, report.Status,
		report.Timestamp.Format(time.RFC3339),
		report.Uptime,
		formatComponentsJSON(report.Components),
		report.Summary.Total,
		report.Summary.Healthy,
		report.Summary.Degraded,
		report.Summary.Unhealthy), nil
}

func formatComponentsJSON(components []ComponentHealth) string {
	if len(components) == 0 {
		return "[]"
	}

	result := "[\n"
	for i, c := range components {
		comma := ","
		if i == len(components)-1 {
			comma = ""
		}
		errorStr := ""
		if c.Error != "" {
			errorStr = fmt.Sprintf(`,"error": "%s"`, c.Error)
		}
		result += fmt.Sprintf(`    {
      "name": "%s",
      "status": "%s",
      "details": "%s",
      "latency": "%s"%s
    }%s`, c.Name, c.Status, c.Details, c.Latency, errorStr, comma)
		if i < len(components)-1 {
			result += "\n"
		}
	}
	result += "\n  ]"
	return result
}

func formatText(report *Report) string {
	result := fmt.Sprintf("Health Report - %s\n", report.Timestamp.Format(time.RFC3339))
	result += fmt.Sprintf("Status: %s | Uptime: %s\n", report.Status, report.Uptime)
	result += "─────────────────────────────────────\n"

	for _, comp := range report.Components {
		statusIcon := "✓"
		if comp.Status == StatusUnhealthy {
			statusIcon = "✗"
		} else if comp.Status == StatusDegraded {
			statusIcon = "⚠"
		} else if comp.Status == StatusUnknown {
			statusIcon = "?"
		}

		details := comp.Details
		if comp.Error != "" {
			details = comp.Error
		}

		result += fmt.Sprintf("  %s %s: %s\n", statusIcon, comp.Name, details)
	}

	result += "─────────────────────────────────────\n"
	result += fmt.Sprintf("Summary: %d healthy, %d degraded, %d unhealthy\n",
		report.Summary.Healthy, report.Summary.Degraded, report.Summary.Unhealthy)

	return result
}

func formatSummary(report *Report) string {
	return fmt.Sprintf("%s | Uptime: %s | %d/%d components healthy",
		report.Status, report.Uptime, report.Summary.Healthy, report.Summary.Total)
}
