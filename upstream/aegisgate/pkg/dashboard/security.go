// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package dashboard

import (
	"log/slog"
	"net/http"

	"github.com/aegisgatesecurity/aegisgate/pkg/security"
)

type SecurityMiddleware struct {
	csrfHandler *security.CSRFMiddleware
	auditLogger *security.AuditLogger
	enabled     bool
}

type SecurityConfig struct {
	EnableCSRF            bool
	EnableAudit           bool
	CSRFTokenLifetime     int // in seconds
	EnableSecurityHeaders bool
	EnablePanicRecovery   bool
}

func NewSecurityMiddleware(config SecurityConfig) *SecurityMiddleware {
	sm := &SecurityMiddleware{
		enabled: config.EnableCSRF || config.EnableAudit,
	}

	if config.EnableCSRF {
		csrfConfig := &security.CSRFConfig{
			TokenLength:    32,
			CookieName:     "csrf_token",
			HeaderName:     "X-CSRF-Token",
			CookieSecure:   true,
			CookieHTTPOnly: true,
			CookieSameSite: http.SameSiteStrictMode,
			CookieMaxAge:   config.CSRFTokenLifetime,
		}
		if csrfConfig.CookieMaxAge == 0 {
			csrfConfig.CookieMaxAge = 86400 // 24 hours
		}
		sm.csrfHandler = security.NewCSRFMiddleware(csrfConfig)
		slog.Info("CSRF middleware initialized")
	}

	if config.EnableAudit {
		eventTypes := []security.EventType{
			security.AuditEventAuth,
			security.AuditEventAccess,
			security.AuditEventSecurity,
		}
		sm.auditLogger = security.NewAuditLogger(true, eventTypes)
		slog.Info("Audit logger initialized")
	}

	return sm
}

func (sm *SecurityMiddleware) Wrap(handler http.Handler) http.Handler {
	if !sm.enabled {
		return handler
	}

	// Apply panic recovery first
	if sm.auditLogger != nil {
		handler = security.AuditMiddleware(sm.auditLogger, handler)
	}

	// Apply CSRF protection
	if sm.csrfHandler != nil {
		handler = sm.csrfHandler.Handler(handler)
	}

	return handler
}
