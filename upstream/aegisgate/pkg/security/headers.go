// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package security provides security middleware for HTTP servers
package security

import (
	"net/http"
	"strings"
)

// SecurityHeadersConfig holds security headers configuration
type SecurityHeadersConfig struct {
	// ContentSecurityPolicy sets CSP header
	ContentSecurityPolicy string
	// XFrameOptions sets X-Frame-Options header
	XFrameOptions string
	// XContentTypeOptions sets X-Content-Type-Options header
	XContentTypeOptions string
	// XXSSProtection sets X-XSS-Protection header
	XXSSProtection string
	// ReferrerPolicy sets Referrer-Policy header
	ReferrerPolicy string
	// StrictTransportSecurity sets HSTS header
	StrictTransportSecurity string
	// PermissionsPolicy sets Permissions-Policy header
	PermissionsPolicy string
	// CrossOriginEmbedderPolicy sets COEP header
	CrossOriginEmbedderPolicy string
	// CrossOriginOpenerPolicy sets COOP header
	CrossOriginOpenerPolicy string
	// CrossOriginResourcePolicy sets CORP header
	CrossOriginResourcePolicy string
}

// DefaultSecurityHeadersConfig returns secure default headers
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data:; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'; " +
			"base-uri 'self'; " +
			"form-action 'self'",
		XFrameOptions:           "DENY",
		XContentTypeOptions:     "nosniff",
		XXSSProtection:          "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		PermissionsPolicy: "accelerometer=(), camera=(), geolocation=(), " +
			"gyroscope=(), magnetometer=(), microphone=(), payment=(), " +
			"usb=()",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
	}
}

// APISecurityHeadersConfig returns headers suitable for APIs
func APISecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentSecurityPolicy:     "default-src 'none'",
		XFrameOptions:             "DENY",
		XContentTypeOptions:       "nosniff",
		XXSSProtection:            "1; mode=block",
		ReferrerPolicy:            "no-referrer",
		StrictTransportSecurity:   "max-age=31536000; includeSubDomains",
		CrossOriginResourcePolicy: "same-origin",
	}
}

// DashboardSecurityHeadersConfig returns headers suitable for web dashboards
func DashboardSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: https:; " +
			"font-src 'self' https://fonts.gstatic.com; " +
			"connect-src 'self' wss: https:; " +
			"frame-ancestors 'none'; " +
			"base-uri 'self'; " +
			"form-action 'self'",
		XFrameOptions:           "DENY",
		XContentTypeOptions:     "nosniff",
		XXSSProtection:          "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		PermissionsPolicy: "accelerometer=(), camera=(), geolocation=(), " +
			"gyroscope=(), magnetometer=(), microphone=(), payment=(), " +
			"usb=()",
	}
}

// SecurityHeadersMiddleware adds security headers to responses
func SecurityHeadersMiddleware(config SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set security headers
			if config.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
			}
			if config.XFrameOptions != "" {
				w.Header().Set("X-Frame-Options", config.XFrameOptions)
			}
			if config.XContentTypeOptions != "" {
				w.Header().Set("X-Content-Type-Options", config.XContentTypeOptions)
			}
			if config.XXSSProtection != "" {
				w.Header().Set("X-XSS-Protection", config.XXSSProtection)
			}
			if config.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", config.ReferrerPolicy)
			}
			if config.StrictTransportSecurity != "" {
				w.Header().Set("Strict-Transport-Security", config.StrictTransportSecurity)
			}
			if config.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", config.PermissionsPolicy)
			}
			if config.CrossOriginEmbedderPolicy != "" {
				w.Header().Set("Cross-Origin-Embedder-Policy", config.CrossOriginEmbedderPolicy)
			}
			if config.CrossOriginOpenerPolicy != "" {
				w.Header().Set("Cross-Origin-Opener-Policy", config.CrossOriginOpenerPolicy)
			}
			if config.CrossOriginResourcePolicy != "" {
				w.Header().Set("Cross-Origin-Resource-Policy", config.CrossOriginResourcePolicy)
			}

			// Remove potentially identifying headers
			w.Header().Del("Server")
			w.Header().Del("X-Powered-By")

			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware adds CORS headers
func CORSMiddleware(allowedOrigins []string, allowedMethods []string, allowedHeaders []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if origin is allowed
			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" || strings.EqualFold(o, origin) {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			// Handle preflight request
			if r.Method == http.MethodOptions {
				if len(allowedMethods) > 0 {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
				}
				if len(allowedHeaders) > 0 {
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
				}
				w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecureHeadersMiddleware is a convenience middleware with default secure headers
func SecureHeadersMiddleware(next http.Handler) http.Handler {
	return SecurityHeadersMiddleware(DefaultSecurityHeadersConfig())(next)
}

// APIHeadersMiddleware is a convenience middleware for API endpoints
func APIHeadersMiddleware(next http.Handler) http.Handler {
	return SecurityHeadersMiddleware(APISecurityHeadersConfig())(next)
}

// DashboardHeadersMiddleware is a convenience middleware for dashboard endpoints
func DashboardHeadersMiddleware(next http.Handler) http.Handler {
	return SecurityHeadersMiddleware(DashboardSecurityHeadersConfig())(next)
}
