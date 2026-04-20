// SPDX-FileCopyrightText: Copyright (C) 2025 AegisGuard Security
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Level Tests
// ============================================================================

func TestLevelString(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LevelFatal, "FATAL"},
		{LevelPanic, "PANIC"},
		{Level(100), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("Level.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"dbg", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"WARN", LevelWarn},
		{"warning", LevelWarn},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"err", LevelError},
		{"fatal", LevelFatal},
		{"FATAL", LevelFatal},
		{"panic", LevelPanic},
		{"PANIC", LevelPanic},
		{"unknown", LevelInfo}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseLevel(tt.input); got != tt.expected {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// Logger Tests
// ============================================================================

func TestNew(t *testing.T) {
	logger := New()
	if logger == nil {
		t.Fatal("New() returned nil")
	}
	if logger.level != LevelInfo {
		t.Errorf("Default level = %v, want %v", logger.level, LevelInfo)
	}
}

func TestNewWithOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewWithOutput(buf)
	if logger.output != buf {
		t.Error("output not set correctly")
	}
}

func TestLoggerOptions(t *testing.T) {
	logger := New(
		WithLevel(LevelDebug),
		WithFormat(FormatText),
		WithField("service", "test"),
	)

	if logger.level != LevelDebug {
		t.Errorf("level = %v, want %v", logger.level, LevelDebug)
	}
	if logger.format != FormatText {
		t.Errorf("format = %v, want %v", logger.format, FormatText)
	}
	if logger.fields["service"] != "test" {
		t.Errorf("fields[service] = %v, want %v", logger.fields["service"], "test")
	}
}

func TestWithLevelString(t *testing.T) {
	logger := New(WithLevelString("debug"))
	if logger.level != LevelDebug {
		t.Errorf("level = %v, want %v", logger.level, LevelDebug)
	}
}

func TestLoggerInfo(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewWithOutput(buf)
	logger.level = LevelInfo
	logger.format = FormatJSON

	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("Output should contain message, got: %s", output)
	}
	if !strings.Contains(output, "INFO") {
		t.Errorf("Output should contain INFO, got: %s", output)
	}
}

func TestLoggerDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewWithOutput(buf)
	logger.level = LevelWarn // Debug is below Warn

	logger.Debug("should not appear")

	if buf.Len() > 0 {
		t.Errorf("Debug message should not appear when level is Warn, got: %s", buf.String())
	}
}

func TestLoggerWithFields(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewWithOutput(buf)
	logger.format = FormatJSON

	logger.WithField("key1", "value1").Info("message", map[string]interface{}{"key2": "value2"})

	output := buf.String()
	if !strings.Contains(output, "key1") || !strings.Contains(output, "value1") {
		t.Errorf("Output should contain key1=value1, got: %s", output)
	}
}

func TestLoggerWithContext(t *testing.T) {
	logger := New(WithField("base", "value"))

	ctxLogger := logger.WithContext(map[string]interface{}{"ctx": "contextual"})

	if _, ok := logger.fields["ctx"]; ok {
		t.Error("Original logger should not have contextual field")
	}
	if _, ok := ctxLogger.fields["ctx"]; !ok {
		t.Error("Context logger should have contextual field")
	}
	if ctxLogger.fields["base"] != "value" {
		t.Error("Context logger should inherit base field")
	}
}

func TestLoggerFatal(t *testing.T) {
	// Fatal exits, so we skip the actual call
	t.Skip("Fatal calls os.Exit which terminates the test")
}

func TestLoggerInfof(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewWithOutput(buf)
	logger.format = FormatJSON

	logger.Infof("value is %d", 42)

	output := buf.String()
	if !strings.Contains(output, "42") {
		t.Errorf("Output should contain formatted value, got: %s", output)
	}
}

// ============================================================================
// Format Tests
// ============================================================================

func TestJSONFormatter(t *testing.T) {
	f := NewJSONFormatter()
	entry := &Entry{
		Timestamp: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		Level:     "INFO",
		Message:   "test",
		Fields:    map[string]interface{}{"key": "value"},
	}

	data, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	if result["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", result["level"])
	}
	if result["message"] != "test" {
		t.Errorf("message = %v, want test", result["message"])
	}
}

func TestTextFormatter(t *testing.T) {
	f := NewTextFormatter()
	entry := &Entry{
		Timestamp: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		Level:     "INFO",
		Message:   "test message",
		Fields:    map[string]interface{}{"key": "value"},
	}

	data, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "INFO") {
		t.Errorf("Output should contain INFO, got: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Output should contain message, got: %s", output)
	}
}

func TestPlainFormatter(t *testing.T) {
	f := NewPlainFormatter()
	entry := &Entry{
		Timestamp: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		Level:     "ERROR",
		Message:   "error occurred",
	}

	data, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "ERROR") {
		t.Errorf("Output should contain ERROR, got: %s", output)
	}
}

// ============================================================================
// Global Logger Tests
// ============================================================================

func TestGlobalLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	SetDefault(NewWithOutput(buf))

	Info("global test")

	output := buf.String()
	if !strings.Contains(output, "global test") {
		t.Errorf("Output should contain message, got: %s", output)
	}
}

func TestConfigure(t *testing.T) {
	buf := &bytes.Buffer{}
	Configure(
		WithOutput(buf),
		WithLevel(LevelWarn),
		WithField("service", "aegisguard"),
	)

	Info("should not appear")
	Warn("should appear")

	if buf.Len() == 0 {
		t.Error("Warning should have been logged")
	}
}

// ============================================================================
// Entry Tests
// ============================================================================

func TestEntryJSON(t *testing.T) {
	entry := &Entry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "test",
		Fields: map[string]interface{}{
			"string": "value",
			"int":    42,
			"bool":   true,
		},
		Caller: "test.go:42",
		Func:   "TestEntryJSON",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if result["level"] != "INFO" {
		t.Errorf("level = %v", result["level"])
	}
	if result["message"] != "test" {
		t.Errorf("message = %v", result["message"])
	}
}

// ============================================================================
// HTTP Handler Tests
// ============================================================================

func TestHTTPHandler(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewWithOutput(buf)
	logger.format = FormatJSON

	handler := NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), logger)

	req := &http.Request{
		Method: "GET",
		URL:    mustParseURL("/test"),
	}

	rr := &responseRecorder{
		headerMap: make(http.Header),
	}
	handler.ServeHTTP(rr, req)

	// Check that log was written
	if buf.Len() == 0 {
		t.Error("Logger should have written something")
	}
}

func TestResponseWriterWrapper(t *testing.T) {
	rr := &responseRecorder{
		headerMap: make(http.Header),
	}

	rr.WriteHeader(http.StatusOK)
	if rr.statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want %d", rr.statusCode, http.StatusOK)
	}

	n, _ := rr.Write([]byte("hello"))
	if n != 5 {
		t.Errorf("Write returned %d, want 5", n)
	}
	if rr.size != 5 {
		t.Errorf("size = %d, want 5", rr.size)
	}
}

// ============================================================================
// Log Group Tests
// ============================================================================

func TestLogGroup(t *testing.T) {
	group := NewLogGroup("req-123")

	group.Add(&Entry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "first",
	})

	time.Sleep(10 * time.Millisecond)

	group.Add(&Entry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "second",
	})

	if len(group.Entries) != 2 {
		t.Errorf("Entries count = %d, want 2", len(group.Entries))
	}

	duration := group.Duration()
	if duration <= 0 {
		t.Error("Duration should be positive")
	}
}

func TestLogGroupToJSON(t *testing.T) {
	group := NewLogGroup("req-456")
	group.Add(&Entry{
		Level:   "INFO",
		Message: "test",
	})

	data, err := group.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error = %v", err)
	}

	if !bytes.Contains(data, []byte("req-456")) {
		t.Errorf("JSON should contain request ID, got: %s", data)
	}
}

// ============================================================================
// Buffered Logger Tests
// ============================================================================

func TestBufferedLogger(t *testing.T) {
	logger := NewBufferedLogger(100)
	logger.Info("buffered message")

	output := logger.String()
	if !strings.Contains(output, "buffered message") {
		t.Errorf("String() should contain message, got: %s", output)
	}

	logger.Reset()
	if logger.String() != "" {
		t.Error("String() should be empty after Reset()")
	}
}

// ============================================================================
// Helpers
// ============================================================================

type responseRecorder struct {
	headerMap  http.Header
	statusCode int
	size       int
}

func (r *responseRecorder) Header() http.Header {
	return r.headerMap
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.size += len(b)
	return len(b), nil
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
