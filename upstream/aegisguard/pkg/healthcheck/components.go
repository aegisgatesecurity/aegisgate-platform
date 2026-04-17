// Package healthcheck provides health monitoring for AegisGuard components
package healthcheck

import (
	"context"
	"sync"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/audit"
	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// ============================================================================
// RBAC HEALTH CHECK
// ============================================================================

// RBACComponent checks the health of the RBAC manager
type RBACComponent struct {
	manager *rbac.Manager
}

// NewRBACComponent creates a new RBAC health check component
func NewRBACComponent(manager *rbac.Manager) Component {
	return &RBACComponent{manager: manager}
}

// Name returns the component name
func (r *RBACComponent) Name() string {
	return "rbac"
}

// Check performs the health check
func (r *RBACComponent) Check(ctx context.Context) *ComponentHealth {
	start := time.Now()

	// Try to list agents - this verifies the manager is functional
	agents := r.manager.ListAgents()

	// Check agent count
	agentCount := len(agents)
	enabledCount := 0
	for _, agent := range agents {
		if agent.Enabled {
			enabledCount++
		}
	}

	// Check sessions
	totalSessions := 0
	for _, agent := range agents {
		sessions := r.manager.GetAgentSessions(agent.ID)
		totalSessions += len(sessions)
	}

	details := ""
	status := StatusHealthy

	if agentCount == 0 {
		details = "No agents registered"
	} else {
		details = "OK"
	}

	return &ComponentHealth{
		Name:        r.Name(),
		Status:      status,
		Details:     details,
		Latency:     time.Since(start),
		LastChecked: time.Now(),
		Metadata: map[string]interface{}{
			"agents_total":   agentCount,
			"agents_enabled": enabledCount,
			"sessions_total": totalSessions,
		},
	}
}

// ============================================================================
// AUDIT HEALTH CHECK
// ============================================================================

// AuditComponent checks the health of the audit logger
type AuditComponent struct {
	logger *audit.Logger
}

// NewAuditComponent creates a new audit health check component
func NewAuditComponent(logger *audit.Logger) Component {
	return &AuditComponent{logger: logger}
}

// Name returns the component name
func (a *AuditComponent) Name() string {
	return "audit"
}

// Check performs the health check
func (a *AuditComponent) Check(ctx context.Context) *ComponentHealth {
	start := time.Now()

	// Test logging capability
	testAction := &audit.Action{
		Type:    "health_check",
		AgentID: "health_check",
		Allowed: true,
		Reason:  "Health check test",
	}

	err := a.logger.LogAction(ctx, testAction)
	if err != nil {
		return &ComponentHealth{
			Name:        a.Name(),
			Status:      StatusUnhealthy,
			Details:     "Failed to write audit log",
			Error:       err.Error(),
			Latency:     time.Since(start),
			LastChecked: time.Now(),
		}
	}

	return &ComponentHealth{
		Name:        a.Name(),
		Status:      StatusHealthy,
		Details:     "Audit logging operational",
		Latency:     time.Since(start),
		LastChecked: time.Now(),
	}
}

// ============================================================================
// COMPONENT HEALTH CHECK
// ============================================================================

// ComponentStatus tracks the health of a single component
type ComponentStatus struct {
	Name        string
	Status      Status
	Details     string
	Error       error
	LastChecked time.Time
	LastHealthy time.Time
	mu          sync.RWMutex
}

// NewComponentStatus creates a new component status tracker
func NewComponentStatus(name string) *ComponentStatus {
	return &ComponentStatus{
		Name:    name,
		Status:  StatusUnknown,
		Details: "Not checked yet",
	}
}

// Update updates the component status
func (c *ComponentStatus) Update(status Status, details string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Status = status
	c.Details = details
	c.Error = err
	c.LastChecked = time.Now()

	if status == StatusHealthy {
		c.LastHealthy = time.Now()
	}
}

// Get returns the current component health
func (c *ComponentStatus) Get() *ComponentHealth {
	c.mu.RLock()
	defer c.mu.RUnlock()

	errStr := ""
	if c.Error != nil {
		errStr = c.Error.Error()
	}

	return &ComponentHealth{
		Name:        c.Name,
		Status:      c.Status,
		Details:     c.Details,
		Error:       errStr,
		LastChecked: c.LastChecked,
	}
}

// TimeSinceHealthy returns duration since last healthy check
func (c *ComponentStatus) TimeSinceHealthy() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.LastHealthy.IsZero() {
		return time.Duration(0)
	}
	return time.Since(c.LastHealthy)
}

// ============================================================================
// COMPOSITE HEALTH CHECK
// ============================================================================

// MultiComponent checks multiple sub-components
type MultiComponent struct {
	name       string
	components map[string]Component
	critical   map[string]bool
	mu         sync.RWMutex
}

// NewMultiComponent creates a new multi-component health check
func NewMultiComponent(name string) *MultiComponent {
	return &MultiComponent{
		name:       name,
		components: make(map[string]Component),
		critical:   make(map[string]bool),
	}
}

// AddComponent adds a sub-component to check
func (m *MultiComponent) AddComponent(name string, component Component, critical bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.components[name] = component
	m.critical[name] = critical
}

// Name returns the component name
func (m *MultiComponent) Name() string {
	return m.name
}

// Check performs the health check on all sub-components
func (m *MultiComponent) Check(ctx context.Context) *ComponentHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()

	overallStatus := StatusHealthy
	errorCount := 0
	criticalUnhealthy := false
	var lastError string

	for name, comp := range m.components {
		health := comp.Check(ctx)

		if health.Status == StatusUnhealthy {
			errorCount++
			lastError = health.Error
			if m.critical[name] {
				criticalUnhealthy = true
			}
		} else if health.Status == StatusDegraded && overallStatus == StatusHealthy {
			overallStatus = StatusDegraded
		}
	}

	if criticalUnhealthy {
		overallStatus = StatusUnhealthy
	} else if errorCount > 0 {
		overallStatus = StatusDegraded
	}

	details := "All components healthy"
	if errorCount > 0 {
		details = lastError
		if criticalUnhealthy {
			details = "Critical component unhealthy: " + lastError
		}
	}

	return &ComponentHealth{
		Name:        m.name,
		Status:      overallStatus,
		Details:     details,
		LastChecked: time.Now(),
		Metadata: map[string]interface{}{
			"components_checked": len(m.components),
			"errors":             errorCount,
		},
	}
}
