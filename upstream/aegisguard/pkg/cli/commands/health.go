// Package commands provides the CLI command implementations for AegisGuard
package commands

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/config"
)

// HealthStatus represents the health status of a component
type HealthStatus struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	Details   string `json:"details,omitempty"`
	Latency   string `json:"latency,omitempty"`
}

// HealthCheck performs a health check on AegisGuard
func HealthCheck(cfg *config.Config, watch bool) error {
	if watch {
		return healthWatch(cfg)
	}
	return healthSingle(cfg)
}

// healthSingle performs a single health check
func healthSingle(cfg *config.Config) error {
	results := performHealthCheck(cfg)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "COMPONENT\tSTATUS\tDETAILS\t")
	fmt.Fprintln(w, "---------\t------\t-------\t")

	allHealthy := true
	for _, result := range results {
		status := "✓ OK"
		if result.Status != "healthy" {
			status = "✗ FAIL"
			allHealthy = false
		}
		if result.Status == "degraded" {
			status = "⚠ WARN"
		}

		details := result.Details
		if result.Latency != "" {
			details = fmt.Sprintf("%s (%s)", result.Details, result.Latency)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t\n", result.Component, status, details)
	}

	w.Flush()

	fmt.Println()
	if allHealthy {
		fmt.Println("✓ AegisGuard is healthy")
	} else {
		fmt.Println("✗ AegisGuard has issues - see components above")
		os.Exit(1)
	}

	return nil
}

// healthWatch continuously monitors health
func healthWatch(cfg *config.Config) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	fmt.Println("Monitoring AegisGuard health (Ctrl+C to exit)")
	fmt.Println("============================================")

	for {
		select {
		case <-ticker.C:
			results := performHealthCheck(cfg)

			// Clear line and print new status
			fmt.Print("\033[2K") // ANSI escape to clear line
			fmt.Print("\033[0G") // Move cursor to beginning

			healthy := 0
			warn := 0
			fail := 0

			for _, r := range results {
				switch r.Status {
				case "healthy":
					healthy++
				case "degraded":
					warn++
				default:
					fail++
				}
			}

			timestamp := time.Now().Format("15:04:05")
			fmt.Printf("[%s] ", timestamp)

			if fail > 0 {
				fmt.Printf("✗ UNHEALTHY (healthy=%d, warn=%d, fail=%d)\n", healthy, warn, fail)
			} else if warn > 0 {
				fmt.Printf("⚠ DEGRADED (healthy=%d, warn=%d, fail=%d)\n", healthy, warn, fail)
			} else {
				fmt.Printf("✓ HEALTHY (healthy=%d, warn=%d, fail=%d)\n", healthy, warn, fail)
			}
		}
	}
}

// performHealthCheck runs all health checks
func performHealthCheck(cfg *config.Config) []HealthStatus {
	results := []HealthStatus{}

	// Check RBAC Manager
	results = append(results, checkRBACManager(cfg))

	// Check Session State
	results = append(results, checkSessions(cfg))

	// Check Agent Count
	results = append(results, checkAgentCount(cfg))

	// Check Config
	results = append(results, checkConfig(cfg))

	return results
}

// checkRBACManager checks if the RBAC manager is operational
func checkRBACManager(cfg *config.Config) HealthStatus {
	start := time.Now()

	mgr, err := getManager(cfg)
	if err != nil {
		return HealthStatus{
			Component: "RBAC Manager",
			Status:    "failed",
			Details:   fmt.Sprintf("Failed to initialize: %v", err),
		}
	}

	// Try to list agents - this verifies the manager is functional
	_ = mgr.ListAgents()

	latency := time.Since(start)

	return HealthStatus{
		Component: "RBAC Manager",
		Status:    "healthy",
		Details:   "Operational",
		Latency:   latency.String(),
	}
}

// checkSessions checks session health
func checkSessions(cfg *config.Config) HealthStatus {
	mgr, err := getManager(cfg)
	if err != nil {
		return HealthStatus{
			Component: "Sessions",
			Status:    "failed",
			Details:   "Manager not available",
		}
	}

	agents := mgr.ListAgents()
	totalSessions := 0
	activeSessions := 0

	for _, agent := range agents {
		sessions := mgr.GetAgentSessions(agent.ID)
		for _, session := range sessions {
			totalSessions++
			if session.IsValid() {
				activeSessions++
			}
		}
	}

	status := "healthy"
	details := fmt.Sprintf("%d total, %d active", totalSessions, activeSessions)

	if activeSessions == 0 && len(agents) > 0 {
		status = "degraded"
		details = "No active sessions"
	}

	return HealthStatus{
		Component: "Sessions",
		Status:    status,
		Details:   details,
	}
}

// checkAgentCount checks agent registration health
func checkAgentCount(cfg *config.Config) HealthStatus {
	mgr, err := getManager(cfg)
	if err != nil {
		return HealthStatus{
			Component: "Agents",
			Status:    "failed",
			Details:   "Manager not available",
		}
	}

	agents := mgr.ListAgents()
	enabledAgents := 0
	disabledAgents := 0

	for _, agent := range agents {
		if agent.Enabled {
			enabledAgents++
		} else {
			disabledAgents++
		}
	}

	details := fmt.Sprintf("%d enabled, %d disabled", enabledAgents, disabledAgents)

	// Check if we're near max capacity
	maxAgents := 1000 // Use default, as SessionConfig doesn't have MaxAgents
	if len(agents) >= maxAgents {
		return HealthStatus{
			Component: "Agents",
			Status:    "degraded",
			Details:   fmt.Sprintf("At capacity (%d/%d)", len(agents), maxAgents),
		}
	}

	return HealthStatus{
		Component: "Agents",
		Status:    "healthy",
		Details:   details,
	}
}

// checkConfig checks configuration health
func checkConfig(cfg *config.Config) HealthStatus {
	if cfg == nil {
		return HealthStatus{
			Component: "Configuration",
			Status:    "failed",
			Details:   "No configuration loaded",
		}
	}

	// Configuration is healthy as long as it loaded (defaults are acceptable)
	details := "Valid"

	// Report any warnings about using defaults
	warnings := []string{}
	if cfg.Session.TTL <= 0 {
		warnings = append(warnings, "session TTL using default (24h)")
	}
	if cfg.Session.MaxSessions <= 0 {
		warnings = append(warnings, "max sessions using default (100)")
	}

	if len(warnings) > 0 {
		details = "Using defaults: " + strings.Join(warnings, ", ")
	}

	return HealthStatus{
		Component: "Configuration",
		Status:    "healthy",
		Details:   details,
	}
}

// GetHealthStatusJSON returns health status as JSON
func GetHealthStatusJSON(cfg *config.Config) (string, error) {
	results := performHealthCheck(cfg)

	type HealthReport struct {
		Status     string         `json:"status"`
		Timestamp  string         `json:"timestamp"`
		Components []HealthStatus `json:"components"`
	}

	report := HealthReport{
		Timestamp:  time.Now().Format(time.RFC3339),
		Components: results,
	}

	// Determine overall status
	allHealthy := true
	hasWarning := false
	for _, r := range results {
		if r.Status != "healthy" {
			allHealthy = false
		}
		if r.Status == "degraded" {
			hasWarning = true
		}
	}

	if allHealthy {
		report.Status = "healthy"
	} else if hasWarning {
		report.Status = "degraded"
	} else {
		report.Status = "unhealthy"
	}

	// Simple JSON output
	return fmt.Sprintf(`{
  "status": "%s",
  "timestamp": "%s",
  "components": [
%s  ]
}`, report.Status, report.Timestamp, formatComponentsJSON(results)), nil
}

func formatComponentsJSON(components []HealthStatus) string {
	result := ""
	for i, c := range components {
		comma := ","
		if i == len(components)-1 {
			comma = ""
		}
		result += fmt.Sprintf(`    {
      "component": "%s",
      "status": "%s",
      "details": "%s",
      "latency": "%s"
    }%s
`, c.Component, c.Status, c.Details, c.Latency, comma)
	}
	return result
}
