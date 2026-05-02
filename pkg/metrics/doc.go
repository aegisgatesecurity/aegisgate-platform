/*
Package metrics provides production-grade Prometheus observability for the
AegisGate Security Platform with built-in cardinality protection.

# Overview

The metrics package exposes HTTP, MCP, tier, audit, and security scan metrics
via Prometheus. All metric labels are designed to be cardinality-safe, preventing
metrics explosion in production.

# Quick Start

For most use cases, simply import and use the package-level functions:

	import "github.com/aegisgatesecurity/aegisgate-platform/pkg/metrics"

	// Record an HTTP request (endpoint is automatically sanitized)
	metrics.RecordHTTPRequest("GET", "/api/v1/users/123", 200, elapsed)

	// Track active connections
	metrics.IncActiveConnections(metrics.ServiceProxy)
	defer metrics.DecActiveConnections(metrics.ServiceProxy)

	// Record an MCP tool invocation
	metrics.RecordMCPRequest("scan_content", metrics.ResultSuccess)

	// Set build info (call once at startup)
	metrics.SetBuildInfo("1.3.0", "go1.22", "linux/amd64", "abc1234")

# Cardinality Safety

All dynamic label values are sanitized to prevent unbounded cardinality:

  - Endpoints: UUIDs, numeric IDs, and MongoDB ObjectIDs are collapsed
    ("/api/v1/users/550e8400-e29b-41d4-a716-446655440000" → "/api/vN/:uuid")
  - Status codes: Grouped into classes (200→"2xx", 404→"4xx")
  - Tool names: Unknown tools are bucketed as "unknown"
  - Client IDs: IP addresses are prefix-bucketed ("192.168.1.100" → "192.168.x.x")

# Label System

Use LabelSet for type-safe label construction:

	ls := metrics.NewLabelSet().
		WithMethod("GET").
		WithEndpoint("/api/v1/users/123").
		WithStatus(200).
		WithService(metrics.ServiceProxy)

# Custom Registries

For testing, create an isolated registry to prevent metric leakage:

	reg := metrics.NewRegistry()
	opts := &metrics.Options{
		Registry: reg,
		// ...
	}

# Middleware

The package provides HTTP middleware that automatically records request duration,
status codes, and active connections:

	handler := metrics.WrapHandler("proxy", myHandler)

Or use the middleware directly:

	mw := metrics.NewMiddleware("dashboard", myHandler)
	http.Handle("/", mw)

# Standard Metric Names

All metrics are prefixed with "aegisgate_":

  - aegisgate_http_requests_total{method, endpoint, status}
  - aegisgate_http_request_duration_seconds{method, endpoint}
  - aegisgate_active_connections{service}
  - aegisgate_rate_limit_hits_total{service, client}
  - aegisgate_security_scans_total{type, result}
  - aegisgate_mcp_connections (gauge)
  - aegisgate_mcp_requests_total{tool, status}
  - aegisgate_tier_requests_total{tier}
  - aegisgate_audit_events_total (counter)
  - aegisgate_build_info{version, goversion, platform}
*/
package metrics
