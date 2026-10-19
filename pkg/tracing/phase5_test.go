// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// resetGlobals cleans up global tracing state between tests.
func resetGlobals(t *testing.T) {
	t.Cleanup(func() {
		shutdownMu.Lock()
		globalShutdown = nil
		shutdownMu.Unlock()
		// Reset to no-op tracer provider
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
	})
}

// ---- InitTracing: enabled with stdout exporter ----

func TestPhase5_InitTracing_StdoutExporter(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "stdout")
	t.Setenv("AEGISGATE_SERVICE_NAME", "test-service")
	t.Setenv("AEGISGATE_VERSION", "v4.7.0")
	t.Setenv("AEGISGATE_TRACE_RATIO", "0.5")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing stdout: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup")
	}
	if err := cleanup(context.Background()); err != nil {
		t.Errorf("cleanup returned error: %v", err)
	}
}

// ---- InitTracing: enabled with OTLP exporter (lazy connection) ----

func TestPhase5_InitTracing_OTLPExporter(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "otlp")
	t.Setenv("AEGISGATE_OTLP_ENDPOINT", "localhost:1") // unreachable but lazy
	t.Setenv("AEGISGATE_SERVICE_NAME", "otlp-test")
	t.Setenv("AEGISGATE_TRACE_RATIO", "0.25")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing otlp: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup")
	}
	// Shutdown should succeed even without a real connection (no spans to flush)
	if err := cleanup(context.Background()); err != nil {
		t.Logf("cleanup returned error (may be expected with fake endpoint): %v", err)
	}
}

// ---- InitTracing: unknown exporter type ----

func TestPhase5_InitTracing_UnknownExporter(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "invalid-type")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, err := InitTracing(context.Background(), logger)
	if err == nil {
		t.Fatal("expected error for unknown exporter type")
	}
	if !strings.Contains(err.Error(), "unknown trace exporter type") {
		t.Errorf("error should mention 'unknown trace exporter type', got: %v", err)
	}
}

// ---- InitTracing: default service name ----

func TestPhase5_InitTracing_DefaultServiceName(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "stdout")
	t.Setenv("AEGISGATE_SERVICE_NAME", "") // should default to aegisgate-platform

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	defer cleanup(context.Background())
}

// ---- InitTracing: default exporter type (otlp) ----

func TestPhase5_InitTracing_DefaultExporterType(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "") // should default to otlp
	t.Setenv("AEGISGATE_OTLP_ENDPOINT", "localhost:1")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	defer cleanup(context.Background())
}

// ---- InitTracing: default OTLP endpoint ----

func TestPhase5_InitTracing_DefaultOTLPEndpoint(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "otlp")
	t.Setenv("AEGISGATE_OTLP_ENDPOINT", "") // should default to localhost:4317

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	defer cleanup(context.Background())
}

// ---- InitTracing: invalid trace ratio (ignored, uses default 0.1) ----

func TestPhase5_InitTracing_InvalidTraceRatio(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "stdout")
	t.Setenv("AEGISGATE_TRACE_RATIO", "not-a-number")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	defer cleanup(context.Background())
}

// ---- InitTracing: trace ratio out of range (negative) ----

func TestPhase5_InitTracing_NegativeTraceRatio(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "stdout")
	t.Setenv("AEGISGATE_TRACE_RATIO", "-0.5")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	defer cleanup(context.Background())
}

// ---- InitTracing: trace ratio > 1 (ignored) ----

func TestPhase5_InitTracing_TraceRatioAboveOne(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "stdout")
	t.Setenv("AEGISGATE_TRACE_RATIO", "1.5")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	defer cleanup(context.Background())
}

// ---- Shutdown: after InitTracing enabled ----

func TestPhase5_Shutdown_AfterInitTracing(t *testing.T) {
	resetGlobals(t)
	t.Setenv("AEGISGATE_TRACING_ENABLED", "true")
	t.Setenv("AEGISGATE_TRACING_EXPORTER", "stdout")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := InitTracing(context.Background(), logger)
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	_ = cleanup

	if err := Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}
}

// ---- Shutdown: without InitTracing (globalShutdown is nil) ----

func TestPhase5_Shutdown_NoGlobalShutdown(t *testing.T) {
	resetGlobals(t)
	shutdownMu.Lock()
	globalShutdown = nil
	shutdownMu.Unlock()

	if err := Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown with nil globalShutdown should return nil, got: %v", err)
	}
}

// ---- Middleware: response with >= 400 status code ----

func TestPhase5_Middleware_StatusCodeAbove400(t *testing.T) {
	resetGlobals(t)
	// Use no-op tracer (default)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	})

	wrapped := Middleware("test-500", handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/error", nil)
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status code: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// ---- Middleware: with trace context propagation headers ----

func TestPhase5_Middleware_WithTraceContextHeaders(t *testing.T) {
	resetGlobals(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware("test-trace-ctx", handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	// Add traceparent header (W3C Trace Context format)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status code: got %d, want %d", rec.Code, http.StatusOK)
	}
}

// ---- sanitizePath: exact UUID path ----

func TestPhase5_SanitizePath_ExactUUID(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	got := sanitizePath(uuid)
	if got != "/api/vN/:uuid" {
		t.Errorf("sanitizePath(%q) = %q, want %q", uuid, got, "/api/vN/:uuid")
	}
}

// ---- sanitizePath: empty path ----

func TestPhase5_SanitizePath_EmptyPath(t *testing.T) {
	got := sanitizePath("")
	if got != "" {
		t.Errorf("sanitizePath(\"\") = %q, want \"\"", got)
	}
}
