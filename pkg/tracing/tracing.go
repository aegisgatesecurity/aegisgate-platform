// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — OpenTelemetry Tracing
// =========================================================================
//
// tracing.go provides distributed tracing via OpenTelemetry. It creates
// a TracerProvider with configurable exporters (OTLP, stdout, no-op)
// and HTTP middleware that propagates trace context across service
// boundaries.
//
// The tracer is opt-in: if AEGISGATE_TRACING_ENABLED is not set or
// "false", InitTracing returns a no-op provider and the middleware
// passes requests through without span creation.
//
// Configuration (env vars):
//
//	AEGISGATE_TRACING_ENABLED=true          — enable tracing
//	AEGISGATE_TRACING_EXPORTER=otlp         — exporter type: otlp, stdout
//	AEGISGATE_OTLP_ENDPOINT=localhost:4317  — OTLP gRPC endpoint
//	AEGISGATE_SERVICE_NAME=aegisgate        — service name for spans
//	AEGISGATE_TRACE_RATIO=0.1              — sample ratio (0.0-1.0)
//
// =========================================================================

package tracing

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	globalShutdown func(context.Context) error
	shutdownMu     sync.Mutex
)

// InitTracing initializes the OpenTelemetry tracer provider based on
// environment variables. If tracing is not enabled, it returns a no-op
// provider. The returned cleanup function must be called on shutdown.
func InitTracing(ctx context.Context, logger *slog.Logger) (func(context.Context) error, error) {
	enabled := strings.ToLower(os.Getenv("AEGISGATE_TRACING_ENABLED")) == "true"
	if !enabled {
		logger.Info("[TRACING] Disabled (set AEGISGATE_TRACING_ENABLED=true to enable)")
		noopTP := trace.NewNoopTracerProvider()
		otel.SetTracerProvider(noopTP)
		return func(context.Context) error { return nil }, nil
	}

	serviceName := os.Getenv("AEGISGATE_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "aegisgate-platform"
	}

	exporterType := os.Getenv("AEGISGATE_TRACING_EXPORTER")
	if exporterType == "" {
		exporterType = "otlp"
	}

	var exporter sdktrace.SpanExporter
	var err error

	switch exporterType {
	case "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout trace exporter: %w", err)
		}
		logger.Info("[TRACING] Using stdout exporter")
	case "otlp":
		endpoint := os.Getenv("AEGISGATE_OTLP_ENDPOINT")
		if endpoint == "" {
			endpoint = "localhost:4317"
		}
		exporter, err = otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
		}
		logger.Info("[TRACING] Using OTLP exporter", "endpoint", endpoint)
	default:
		return nil, fmt.Errorf("unknown trace exporter type: %s (supported: otlp, stdout)", exporterType)
	}

	// Build resource with service name and attributes
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(os.Getenv("AEGISGATE_VERSION")),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace resource: %w", err)
	}

	// Parse sample ratio
	ratio := 0.1
	if r := os.Getenv("AEGISGATE_TRACE_RATIO"); r != "" {
		var parsed float64
		if _, err := fmt.Sscanf(r, "%f", &parsed); err == nil && parsed >= 0 && parsed <= 1 {
			ratio = parsed
		}
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(ratio)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Store the shutdown function so that Shutdown() can be called
	// from anywhere in the codebase (e.g., signal handlers).
	shutdownMu.Lock()
	globalShutdown = tp.Shutdown
	shutdownMu.Unlock()

	logger.Info("[TRACING] OpenTelemetry tracing initialized",
		"service", serviceName, "exporter", exporterType, "sample_ratio", ratio)

	return tp.Shutdown, nil
}

// Middleware wraps an http.Handler with OpenTelemetry tracing. Each
// request creates a span with the HTTP method and path. If tracing is
// disabled, this is a no-op pass-through.
func Middleware(name string, next http.Handler) http.Handler {
	tracer := otel.GetTracerProvider().Tracer("aegisgate-platform")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// Extract propagated trace context from headers
		ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(r.Header))
		spanName := fmt.Sprintf("%s %s", r.Method, sanitizePath(r.URL.Path))
		ctx, span := tracer.Start(ctx, spanName,
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPathKey.String(r.URL.Path),
			),
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		// Wrap response writer to capture status code
		wrapped := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		span.SetAttributes(semconv.HTTPResponseStatusCodeKey.Int(wrapped.statusCode))
		if wrapped.statusCode >= 400 {
		}
	})
}

// StartSpan creates a child span for use in application code. If tracing
// is disabled, the returned span is no-op. Always call span.End() when done.
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	tracer := otel.GetTracerProvider().Tracer("aegisgate-platform")
	return tracer.Start(ctx, name)
}

// Shutdown gracefully flushes pending spans and shuts down the exporter.
func Shutdown(ctx context.Context) error {
	shutdownMu.Lock()
	defer shutdownMu.Unlock()
	if globalShutdown != nil {
		return globalShutdown(ctx)
	}
	return nil
}

// statusWriter wraps http.ResponseWriter to capture the status code
type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// sanitizePath reduces high-cardinality paths for span names
func sanitizePath(path string) string {
	// Replace UUIDs
	if len(path) == 36 && path[8] == '-' && path[13] == '-' {
		return "/api/vN/:uuid"
	}
	return path
}
