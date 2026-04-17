// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package security provides essential security middleware and utilities for AegisGate.
// This includes panic recovery, CSRF protection, XSS prevention, and audit logging.
package security

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// PanicRecoveryMiddleware recovers from panics and returns a safe error response
type PanicRecoveryMiddleware struct {
	logger *slog.Logger
}

// NewPanicRecoveryMiddleware creates a new panic recovery middleware
func NewPanicRecoveryMiddleware() *PanicRecoveryMiddleware {
	return &PanicRecoveryMiddleware{
		logger: slog.Default().WithGroup("security.recovery"),
	}
}

// WithLogger sets a custom logger
func (prm *PanicRecoveryMiddleware) WithLogger(logger *slog.Logger) *PanicRecoveryMiddleware {
	prm.logger = logger.WithGroup("security.recovery")
	return prm
}

// Handler wraps an http.Handler with panic recovery
func (prm *PanicRecoveryMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := debug.Stack()
				prm.logger.Error("Panic recovered",
					"error", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
					"stack", string(stack),
				)

				// Return a safe error response
				w.WriteHeader(http.StatusInternalServerError)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success":   false,
					"error":     "Internal server error",
					"timestamp": time.Now(),
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecureHandlerFunc wraps a function with panic recovery
func SecureHandlerFunc(fn func(w http.ResponseWriter, r *http.Request) error) func(w http.ResponseWriter, r *http.Request) {
	logger := slog.Default().WithGroup("security.recovery")
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := debug.Stack()
				logger.Error("Panic recovered",
					"error", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
					"stack", string(stack),
				)
				w.WriteHeader(http.StatusInternalServerError)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success":   false,
					"error":     "Internal server error",
					"timestamp": time.Now(),
				})
			}
		}()
		if err := fn(w, r); err != nil {
			logger.Error("Handler error", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":   false,
				"error":     err.Error(),
				"timestamp": time.Now(),
			})
		}
	}
}

// SecureHandler wraps an http.HandlerFunc with panic recovery
func SecureHandler(fn http.HandlerFunc) http.HandlerFunc {
	logger := slog.Default().WithGroup("security.recovery")
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := debug.Stack()
				logger.Error("Panic recovered",
					"error", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
					"stack", string(stack),
				)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		fn(w, r)
	}
}

// RecoveryOptions configures panic recovery behavior
type RecoveryOptions struct {
	// EnableStackTrace includes stack traces in logs
	EnableStackTrace bool
	// LogLevel controls the log level for recovered panics
	LogLevel slog.Level
}

// DefaultRecoveryOptions returns default recovery options
func DefaultRecoveryOptions() *RecoveryOptions {
	return &RecoveryOptions{
		EnableStackTrace: true,
		LogLevel:         slog.LevelError,
	}
}

// AdvancedRecoveryMiddleware provides configurable panic recovery
type AdvancedRecoveryMiddleware struct {
	options *RecoveryOptions
	logger  *slog.Logger
}

// NewAdvancedRecoveryMiddleware creates recovery middleware with options
func NewAdvancedRecoveryMiddleware(opts *RecoveryOptions) *AdvancedRecoveryMiddleware {
	return &AdvancedRecoveryMiddleware{
		options: opts,
		logger:  slog.Default().WithGroup("security.recovery"),
	}
}

// Handler wraps a handler with advanced panic recovery
func (arm *AdvancedRecoveryMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logAttrs := []any{
					"error", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
				}
				if arm.options.EnableStackTrace {
					logAttrs = append(logAttrs, "stack", string(debug.Stack()))
				}

				switch arm.options.LogLevel {
				case slog.LevelDebug:
					arm.logger.Debug("Panic recovered", logAttrs...)
				case slog.LevelInfo:
					arm.logger.Info("Panic recovered", logAttrs...)
				case slog.LevelWarn:
					arm.logger.Warn("Panic recovered", logAttrs...)
				default:
					arm.logger.Error("Panic recovered", logAttrs...)
				}

				w.WriteHeader(http.StatusInternalServerError)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success":   false,
					"error":     "Internal server error",
					"timestamp": time.Now(),
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
