// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package security provides security middleware for HTTP servers
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// RecoveryConfig holds panic recovery configuration
type RecoveryConfig struct {
	// LogPanics logs panic details
	LogPanics bool
	// StackTrace enables stack trace logging
	StackTrace bool
	// CustomHandler allows custom panic response
	CustomHandler func(w http.ResponseWriter, r *http.Request, panicValue interface{})
}

// DefaultRecoveryConfig returns default recovery configuration
func DefaultRecoveryConfig() RecoveryConfig {
	return RecoveryConfig{
		LogPanics:  true,
		StackTrace: true,
	}
}

// RecoveryMiddleware creates a panic recovery middleware
func RecoveryMiddleware(next http.Handler) http.Handler {
	return RecoveryMiddlewareWithConfig(DefaultRecoveryConfig())(next)
}

// RecoveryMiddlewareWithConfig creates a panic recovery middleware with configuration
func RecoveryMiddlewareWithConfig(config RecoveryConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Collect stack trace
					stack := debug.Stack()

					// Log the panic
					if config.LogPanics {
						slog.Error("Panic recovered",
							"error", fmt.Sprintf("%v", err),
							"path", r.URL.Path,
							"method", r.Method,
							"remote_addr", r.RemoteAddr,
							"stack", string(stack),
						)
					}

					// Use custom handler if provided
					if config.CustomHandler != nil {
						config.CustomHandler(w, r, err)
						return
					}

					// Default error response
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)

					errorResponse := map[string]interface{}{
						"success": false,
						"error":   "Internal Server Error",
						"message": "An unexpected error occurred. The incident has been logged.",
					}

					json.NewEncoder(w).Encode(errorResponse)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// RecoveryHandler wraps a http.HandlerFunc with panic recovery
func RecoveryHandler(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stack := debug.Stack()
				slog.Error("Panic recovered in handler",
					"error", fmt.Sprintf("%v", err),
					"path", r.URL.Path,
					"method", r.Method,
					"remote_addr", r.RemoteAddr,
					"stack", string(stack),
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "Internal Server Error",
				})
			}
		}()
		fn(w, r)
	}
}

// SafeExecute runs a function with panic recovery and returns any error
func SafeExecute(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			slog.Error("Panic recovered in SafeExecute",
				"error", fmt.Sprintf("%v", r),
				"stack", string(stack),
			)
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn()
}

// SafeExecuteWithContext runs a function with panic recovery and context
func SafeExecuteWithContext(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			slog.Error("Panic recovered in SafeExecuteWithContext",
				"error", fmt.Sprintf("%v", r),
				"stack", string(stack),
			)
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(ctx)
}
