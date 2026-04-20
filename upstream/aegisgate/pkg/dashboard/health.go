// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package dashboard provides HTTP handlers and API endpoints for AegisGate's
// real-time monitoring interface.
package dashboard

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/i18n"
)

// handleLiveness handles GET /health/live
// Returns OK if the service is running (liveness probe for Kubernetes)
func (d *Dashboard) handleLiveness(w http.ResponseWriter, r *http.Request) error {
	locale := d.getLocaleFromRequest(r)
	health := map[string]interface{}{
		"status":    d.t(locale, "health.status_ok"),
		"timestamp": time.Now(),
		"uptime":    time.Since(d.startTime).Seconds(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
	return nil
}

// handleReadiness handles GET /health/ready
// Returns OK if the service is ready to accept traffic
func (d *Dashboard) handleReadiness(w http.ResponseWriter, r *http.Request) error {
	locale := d.getLocaleFromRequest(r)
	checks := make(map[string]bool)
	if d.metrics != nil {
		checks["metrics"] = true
	} else {
		checks["metrics"] = false
	}
	if d.sseServer != nil {
		checks["websocket"] = true
	} else {
		checks["websocket"] = false
	}
	if d.server != nil {
		checks["http_server"] = true
	} else {
		checks["http_server"] = false
	}
	ready := true
	for _, check := range checks {
		if !check {
			ready = false
			break
		}
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}

	checksLocalized := make(map[string]string)
	for name, ok := range checks {
		if ok {
			checksLocalized[name] = d.t(locale, "health.check_ok")
		} else {
			checksLocalized[name] = d.t(locale, "health.check_failed")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ready":     ready,
		"status":    d.tWith(locale, "health.readiness_status", map[string]interface{}{"Status": readyStr(ready)}),
		"checks":    checksLocalized,
		"timestamp": time.Now(),
	})
	return nil
}

// handleDetailedHealth handles GET /api/health/detailed
// Returns detailed health information including system metrics
func (d *Dashboard) handleDetailedHealth(w http.ResponseWriter, r *http.Request) error {
	locale := d.getLocaleFromRequest(r)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	healthData := map[string]interface{}{
		"health": map[string]interface{}{
			"status":    d.t(locale, "health.status_healthy"),
			"timestamp": time.Now(),
			"uptime":    time.Since(d.startTime).Seconds(),
			"components": map[string]string{
				"metrics":   d.t(locale, "health.check_ok"),
				"websocket": d.t(locale, "health.check_ok"),
				"http":      d.t(locale, "health.check_ok"),
			},
		},
		"system": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"memory_mb":  memStats.Alloc / (1024 * 1024),
			"heap_mb":    memStats.HeapAlloc / (1024 * 1024),
		},
	}

	// Add locale info if i18n is enabled
	if d.i18n != nil {
		healthData["locale"] = string(d.i18n.GetCurrent())
	}

	d.writeJSON(w, http.StatusOK, APIResponse{
		Success:   true,
		Data:      healthData,
		Timestamp: time.Now(),
	})
	return nil
}

// readyStr returns a localized ready/not ready string
func readyStr(ready bool) string {
	if ready {
		return "ready"
	}
	return "not ready"
}

// GetI18nManager returns the i18n manager for external access
func (d *Dashboard) GetI18nManager() *i18n.Manager {
	return d.i18n
}

// SetLocale sets the current locale
func (d *Dashboard) SetLocale(locale i18n.Locale) error {
	if d.i18n == nil {
		return nil
	}
	return d.i18n.SetCurrent(locale)
}
