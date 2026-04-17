// Package healthcheck provides health monitoring for AegisGuard components
package healthcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ============================================================================
// HTTP SERVER
// ============================================================================

// Server provides HTTP handlers for health endpoints
type Server struct {
	checker     *Checker
	mux         *http.ServeMux
	readinessFn func(ctx context.Context) *ComponentHealth
}

// NewServer creates a new health check HTTP server
func NewServer(checker *Checker) *Server {
	s := &Server{
		checker: checker,
		mux:     http.NewServeMux(),
	}

	// Register default routes
	s.mux.HandleFunc("/health", s.HandleHealth)
	s.mux.HandleFunc("/health/live", s.HandleLiveness)
	s.mux.HandleFunc("/health/ready", s.HandleReadiness)
	s.mux.HandleFunc("/health/startup", s.HandleStartup)

	return s
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	return s.mux
}

// SetReadinessCheck sets a custom readiness check function
func (s *Server) SetReadinessCheck(fn func(ctx context.Context) *ComponentHealth) {
	s.readinessFn = fn
}

// HandleHealth returns full health report
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	report := s.checker.Check(ctx)

	// Check for format parameter
	format := r.URL.Query().Get("format")

	switch format {
	case "json":
		s.writeJSON(w, r, http.StatusOK, report)
	default:
		// Default to text for browser, JSON for API calls
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			s.writeJSON(w, r, http.StatusOK, report)
		} else {
			s.writeText(w, r, http.StatusOK, report)
		}
	}
}

// HandleLiveness returns simple liveness check
func (s *Server) HandleLiveness(w http.ResponseWriter, r *http.Request) {
	health := &ComponentHealth{
		Name:        "liveness",
		Status:      StatusHealthy,
		Details:     "Server is alive",
		LastChecked: time.Now(),
	}

	statusCode := http.StatusOK
	if health.Status != StatusHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	s.writeJSON(w, r, statusCode, health)
}

// HandleReadiness returns readiness check
func (s *Server) HandleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var health *ComponentHealth
	if s.readinessFn != nil {
		health = s.readinessFn(ctx)
	} else {
		health = s.checkReadiness(ctx)
	}

	statusCode := http.StatusOK
	if health.Status != StatusHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	s.writeJSON(w, r, statusCode, health)
}

// HandleStartup returns startup check
func (s *Server) HandleStartup(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	report := s.checker.Check(ctx)

	// Consider startup complete if critical components are ready
	status := StatusHealthy
	details := "Startup complete"

	for _, comp := range report.Components {
		if comp.Status == StatusUnhealthy {
			status = StatusUnhealthy
			details = fmt.Sprintf("Component %s is unhealthy", comp.Name)
			break
		}
	}

	health := &ComponentHealth{
		Name:        "startup",
		Status:      status,
		Details:     details,
		LastChecked: time.Now(),
	}

	statusCode := http.StatusOK
	if health.Status != StatusHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	s.writeJSON(w, r, statusCode, health)
}

// checkReadiness performs a readiness check
func (s *Server) checkReadiness(ctx context.Context) *ComponentHealth {
	report := s.checker.Check(ctx)

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

// writeJSON writes JSON response
func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeText writes text response
func (s *Server) writeText(w http.ResponseWriter, r *http.Request, status int, report *Report) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	if text, err := FormatReport(report, "text"); err == nil {
		fmt.Fprintln(w, text)
	}
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

// Middleware provides health check middleware for integration with existing servers
type Middleware struct {
	checker *Checker
}

// NewMiddleware creates a new health check middleware
func NewMiddleware(checker *Checker) *Middleware {
	return &Middleware{checker: checker}
}

// HealthHandler returns an HTTP handler for health checks
func (m *Middleware) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		report := m.checker.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		if report.IsHealthy() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(report)
	}
}

// LiveHandler returns a simple liveness handler
func (m *Middleware) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "alive",
		})
	}
}

// ReadyHandler returns a readiness handler
func (m *Middleware) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		report := m.checker.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		if report.IsHealthy() {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "ready",
			})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			summary, _ := FormatReport(report, "summary")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "not_ready",
				"report": summary,
			})
		}
	}
}

// ============================================================================
// WEB UI
// ============================================================================

// DashboardHandler returns an HTML dashboard for health monitoring
func DashboardHandler(checker *Checker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		report := checker.Check(ctx)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		html := `<!DOCTYPE html>
<html>
<head>
    <title>AegisGuard Health Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; }
        .status { padding: 20px; margin: 10px 0; border-radius: 8px; }
        .healthy { background: #0d3d0d; border: 2px solid #00ff00; }
        .degraded { background: #3d3d00; border: 2px solid #ffff00; }
        .unhealthy { background: #3d0d0d; border: 2px solid #ff0000; }
        .component { padding: 15px; margin: 10px 0; background: #16213e; border-radius: 5px; }
        .component-name { font-weight: bold; color: #00d4ff; }
        .latency { color: #888; font-size: 0.9em; }
        .error { color: #ff6b6b; }
        .summary { margin: 20px 0; padding: 15px; background: #0f3460; border-radius: 8px; }
        .refresh { margin: 20px 0; }
        .refresh a { color: #00d4ff; }
    </style>
</head>
<body>
    <h1>AegisGuard Health Dashboard</h1>
    <div class="summary">
        <h2>Overall Status: <span style="color: %s">%s</span></h2>
        <p>Uptime: %s | Checked: %s</p>
        <p>Healthy: %d | Degraded: %d | Unhealthy: %d</p>
    </div>
    <div class="refresh">
        <a href="?refresh=1">Auto-refresh in 5s</a> | <a href="/health">JSON</a>
    </div>
    <h2>Components</h2>
    %s
</body>
</html>`

		statusColor := "#00ff00"
		if report.Status == string(StatusDegraded) {
			statusColor = "#ffff00"
		} else if report.Status == string(StatusUnhealthy) {
			statusColor = "#ff0000"
		}

		componentsHTML := ""
		for _, comp := range report.Components {
			errorHTML := ""
			if comp.Error != "" {
				errorHTML = fmt.Sprintf(`<p class="error">Error: %s</p>`, comp.Error)
			}

			componentsHTML += fmt.Sprintf(`<div class="component">
                <span class="component-name">%s</span> - <span>%s</span>
                <p class="latency">Latency: %s | Checked: %s</p>
                %s
            </div>`, comp.Name, comp.Status, comp.Latency, comp.LastChecked.Format(time.RFC3339), errorHTML)
		}

		if componentsHTML == "" {
			componentsHTML = "<p>No components registered</p>"
		}

		fmt.Fprintf(w, html,
			statusColor,
			strings.ToUpper(report.Status),
			report.Uptime,
			report.Timestamp.Format(time.RFC3339),
			report.Summary.Healthy,
			report.Summary.Degraded,
			report.Summary.Unhealthy,
			componentsHTML,
		)
	}
}
