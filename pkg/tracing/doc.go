// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package tracing provides OpenTelemetry tracing integration for the
// AegisGate Security Platform.
//
// Tracing is disabled by default. Set AEGISGATE_TRACING_ENABLED=true
// to enable OTLP export to a configured collector endpoint. When
// enabled, the package provides:
//
//   - InitTracing: Initializes the OTLP exporter and tracer provider,
//     returning a shutdown function for graceful cleanup.
//   - Middleware: HTTP middleware that creates a span for each
//     incoming request, recording method, path, status code, and
//     duration. Paths are sanitized to avoid high-cardinality span
//     names (e.g., /api/v1/audit/events/{id} → /api/v1/audit/events/:id).
//   - StartSpan: Manual span creation for custom instrumentation in
//     business logic.
//   - Shutdown: Flushes pending spans and shuts down the exporter.
//
// The package uses the OpenTelemetry Go SDK with the OTLP HTTP exporter.
// Service name is set to "aegisgate-platform" and can be overridden via
// AEGISGATE_TRACING_SERVICE_NAME.
// =========================================================================
package tracing
