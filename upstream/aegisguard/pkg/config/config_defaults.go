// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 AegisGuard Security

package config

import "time"

// Default configuration values for AegisGuard
const (
	DefaultHTTPPort            = 8080
	DefaultGRPCPort            = 9090
	DefaultMetricsPort         = 9091
	DefaultHealthCheckInterval = 30 * time.Second
	DefaultSessionTimeout      = 24 * time.Hour
	DefaultMaxRequestSize      = 10 * 1024 * 1024 // 10MB
	DefaultRateLimit           = 1000
	DefaultRateLimitWindow     = 1 * time.Minute
	DefaultLogLevel            = "info"
	DefaultAuditLogRetention   = 90 * 24 * time.Hour // 90 days
	DefaultCacheSize           = 1000
	DefaultCacheTTL            = 5 * time.Minute
	DefaultMaxWorkers          = 10
	DefaultMaxRetries          = 3
	DefaultRetryDelay          = 1 * time.Second
	DefaultMaxBackoff          = 30 * time.Second
	DefaultProxyTimeout        = 60 * time.Second
)

// Default configuration for compliance checks
const (
	DefaultComplianceCheckTimeout = 5 * time.Second
	DefaultPatternCacheSize       = 1000
	DefaultPatternCacheTTL        = 10 * time.Minute
)

// Default database configuration
const (
	DefaultDBPath            = "./data/aegisguard.db"
	DefaultDBMaxOpenConns    = 10
	DefaultDBMaxIdleConns    = 5
	DefaultDBConnMaxLifetime = 5 * time.Minute
)

// Default security configuration
const (
	DefaultJWTSecret           = ""
	DefaultJWTExpiration       = 24 * time.Hour
	DefaultPasswordMinLength   = 12
	DefaultPasswordComplexity  = 3
	DefaultSessionKeyLength    = 32
	DefaultCSRFTokenLength     = 32
	DefaultEncryptionKeyLength = 32
)

// Default network configuration
const (
	DefaultMaxConnections = 1000
	DefaultIdleTimeout    = 5 * time.Minute
)

// Default feature flags
const (
	DefaultEnableRBAC          = true
	DefaultEnableRateLimiting  = true
	DefaultEnableAuditLogging  = true
	DefaultEnableHealthChecks  = true
	DefaultEnableMetrics       = true
	DefaultEnableTracing       = false
	DefaultEnableDebugMode     = false
	DefaultEnableCompliance    = true
	DefaultEnableSandboxing    = true
	DefaultEnableWorkflowGuard = true
)
