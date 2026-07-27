// Package healthcheck provides health monitoring for AegisGuard components
package healthcheck

import (
	"context"
	"testing"
	"time"
)

// TestHealthStatus tests status constants
func TestHealthStatus(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusHealthy, "healthy"},
		{StatusDegraded, "degraded"},
		{StatusUnhealthy, "unhealthy"},
		{StatusUnknown, "unknown"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.expected {
			t.Errorf("Status %v: got %s, want %s", tt.status, string(tt.status), tt.expected)
		}
	}
}

// TestComponentHealth tests component health struct
func TestComponentHealth(t *testing.T) {
	health := &ComponentHealth{
		Name:        "test",
		Status:      StatusHealthy,
		Details:     "OK",
		Latency:     100 * time.Millisecond,
		LastChecked: time.Now(),
	}

	if health.Name != "test" {
		t.Errorf("Name: got %s, want test", health.Name)
	}
	if health.Status != StatusHealthy {
		t.Errorf("Status: got %s, want %s", health.Status, StatusHealthy)
	}
}

// TestBaseComponent tests the base component implementation
func TestBaseComponent(t *testing.T) {
	checkCalled := false

	comp := NewComponent("test-component", func(ctx context.Context) *ComponentHealth {
		checkCalled = true
		return &ComponentHealth{
			Name:    "test-component",
			Status:  StatusHealthy,
			Details: "OK",
		}
	})

	if comp.Name() != "test-component" {
		t.Errorf("Name: got %s, want test-component", comp.Name())
	}

	ctx := context.Background()
	health := comp.Check(ctx)

	if !checkCalled {
		t.Error("Check was not called")
	}

	if health.Status != StatusHealthy {
		t.Errorf("Status: got %s, want %s", health.Status, StatusHealthy)
	}
}

// TestChecker tests the health checker
func TestChecker(t *testing.T) {
	checker := NewChecker()

	// Register a component
	checker.Register(NewComponent("comp1", func(ctx context.Context) *ComponentHealth {
		return &ComponentHealth{
			Name:    "comp1",
			Status:  StatusHealthy,
			Details: "OK",
		}
	}))

	// Check component is registered
	components := checker.ListComponents()
	if len(components) != 1 {
		t.Errorf("Components: got %d, want 1", len(components))
	}

	// Perform check
	ctx := context.Background()
	report := checker.Check(ctx)

	if report.Status != string(StatusHealthy) {
		t.Errorf("Report status: got %s, want %s", report.Status, StatusHealthy)
	}

	if len(report.Components) != 1 {
		t.Errorf("Components in report: got %d, want 1", len(report.Components))
	}

	// Check specific component
	health := checker.CheckComponent(ctx, "comp1")
	if health.Status != StatusHealthy {
		t.Errorf("CheckComponent: got %s, want %s", health.Status, StatusHealthy)
	}

	// Check unknown component returns unknown
	health = checker.CheckComponent(ctx, "unknown")
	if health.Status != StatusUnknown {
		t.Errorf("Unknown component: got %s, want %s", health.Status, StatusUnknown)
	}

	// Unregister
	checker.Unregister("comp1")
	components = checker.ListComponents()
	if len(components) != 0 {
		t.Errorf("After unregister: got %d, want 0", len(components))
	}
}

// TestReport tests the health report
func TestReport(t *testing.T) {
	report := &Report{
		Status:    string(StatusHealthy),
		Timestamp: time.Now(),
		Components: []ComponentHealth{
			{Name: "comp1", Status: StatusHealthy},
			{Name: "comp2", Status: StatusDegraded},
		},
		Summary: &Summary{
			Total:     2,
			Healthy:   1,
			Degraded:  1,
			Unhealthy: 0,
		},
	}

	if !report.IsHealthy() {
		t.Error("Report with degraded should still be healthy")
	}

	report.Status = string(StatusUnhealthy)
	if report.IsHealthy() {
		t.Error("Report with unhealthy should not be healthy")
	}

	if !report.HasIssues() {
		t.Error("Unhealthy report should have issues")
	}

	report.Status = string(StatusUnhealthy)
	if !report.HasIssues() {
		t.Error("Unhealthy report should have issues")
	}

	// Get component
	comp := report.GetComponent("comp1")
	if comp == nil {
		t.Error("GetComponent should return component")
	}

	comp = report.GetComponent("nonexistent")
	if comp != nil {
		t.Error("GetComponent should return nil for unknown")
	}
}

// TestCheckAll tests checking all components
func TestCheckAll(t *testing.T) {
	ctx := context.Background()

	components := []Component{
		NewComponent("healthy", func(ctx context.Context) *ComponentHealth {
			return &ComponentHealth{Name: "healthy", Status: StatusHealthy}
		}),
		NewComponent("degraded", func(ctx context.Context) *ComponentHealth {
			return &ComponentHealth{Name: "degraded", Status: StatusDegraded}
		}),
		NewComponent("unhealthy", func(ctx context.Context) *ComponentHealth {
			return &ComponentHealth{Name: "unhealthy", Status: StatusUnhealthy, Error: "test error"}
		}),
	}

	report := CheckAll(ctx, components)

	if report.Summary.Total != 3 {
		t.Errorf("Total: got %d, want 3", report.Summary.Total)
	}
	if report.Summary.Healthy != 1 {
		t.Errorf("Healthy: got %d, want 1", report.Summary.Healthy)
	}
	if report.Summary.Degraded != 1 {
		t.Errorf("Degraded: got %d, want 1", report.Summary.Degraded)
	}
	if report.Summary.Unhealthy != 1 {
		t.Errorf("Unhealthy: got %d, want 1", report.Summary.Unhealthy)
	}

	// Overall status should be unhealthy because there's at least one unhealthy
	if report.Status != string(StatusUnhealthy) {
		t.Errorf("Overall status: got %s, want %s", report.Status, StatusUnhealthy)
	}
}

// TestMultiComponent tests multi-component health check
func TestMultiComponent(t *testing.T) {
	ctx := context.Background()

	multi := NewMultiComponent("parent")

	multi.AddComponent("sub1", NewComponent("sub1", func(ctx context.Context) *ComponentHealth {
		return &ComponentHealth{Name: "sub1", Status: StatusHealthy}
	}), true)

	multi.AddComponent("sub2", NewComponent("sub2", func(ctx context.Context) *ComponentHealth {
		return &ComponentHealth{Name: "sub2", Status: StatusDegraded}
	}), false)

	multi.AddComponent("sub3", NewComponent("sub3", func(ctx context.Context) *ComponentHealth {
		return &ComponentHealth{Name: "sub3", Status: StatusUnhealthy, Error: "failed"}
	}), false)

	health := multi.Check(ctx)

	// Non-critical degraded should make overall degraded
	if health.Status != StatusDegraded {
		t.Errorf("Status: got %s, want degraded", health.Status)
	}

	// Now make critical unhealthy
	multi2 := NewMultiComponent("parent2")
	multi2.AddComponent("critical", NewComponent("critical", func(ctx context.Context) *ComponentHealth {
		return &ComponentHealth{Name: "critical", Status: StatusUnhealthy, Error: "critical failure"}
	}), true)

	health2 := multi2.Check(ctx)
	if health2.Status != StatusUnhealthy {
		t.Errorf("Critical unhealthy: got %s, want unhealthy", health2.Status)
	}
}

// TestFormatReport tests report formatting
func TestFormatReport(t *testing.T) {
	report := &Report{
		Status:    string(StatusHealthy),
		Timestamp: time.Now(),
		Uptime:    1 * time.Hour,
		Components: []ComponentHealth{
			{
				Name:    "test",
				Status:  StatusHealthy,
				Details: "OK",
				Latency: 10 * time.Millisecond,
			},
		},
		Summary: &Summary{
			Total:     1,
			Healthy:   1,
			Degraded:  0,
			Unhealthy: 0,
		},
	}

	// Test text format
	text, err := FormatReport(report, "text")
	if err != nil {
		t.Errorf("FormatReport text: %v", err)
	}
	if text == "" {
		t.Error("Text format should not be empty")
	}

	// Test summary format
	summary, err := FormatReport(report, "summary")
	if err != nil {
		t.Errorf("FormatReport summary: %v", err)
	}
	if summary == "" {
		t.Error("Summary format should not be empty")
	}

	// Test JSON format
	json, err := FormatReport(report, "json")
	if err != nil {
		t.Errorf("FormatReport json: %v", err)
	}
	if json == "" {
		t.Error("JSON format should not be empty")
	}
}

// TestComponentStatus tests the component status tracker
func TestComponentStatus(t *testing.T) {
	status := NewComponentStatus("test")

	// Initial state
	health := status.Get()
	if health.Status != StatusUnknown {
		t.Errorf("Initial status: got %s, want unknown", health.Status)
	}

	// Update to healthy
	status.Update(StatusHealthy, "All good", nil)
	health = status.Get()
	if health.Status != StatusHealthy {
		t.Errorf("After healthy update: got %s, want healthy", health.Status)
	}

	// Check time since healthy
	time.Sleep(10 * time.Millisecond)
	duration := status.TimeSinceHealthy()
	if duration <= 0 {
		t.Error("TimeSinceHealthy should be positive")
	}

	// Update to unhealthy
	status.Update(StatusUnhealthy, "Failed", nil)
	health = status.Get()
	if health.Status != StatusUnhealthy {
		t.Errorf("After unhealthy update: got %s, want unhealthy", health.Status)
	}
}
