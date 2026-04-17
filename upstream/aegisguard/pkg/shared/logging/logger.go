// SPDX-FileCopyrightText: Copyright (C) 2025 AegisGuard Security
// SPDX-License-Identifier: MIT

// Package logging provides structured JSON logging for AegisGuard.
// Supports multiple log levels, structured fields, and various output formats.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ============================================================================
// Log Level
// ============================================================================

// Level represents the severity of a log message
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
	LevelPanic
)

// String returns the string representation of the level
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	case LevelPanic:
		return "PANIC"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a level string
func ParseLevel(s string) Level {
	switch s {
	case "debug", "DEBUG", "dbg":
		return LevelDebug
	case "info", "INFO":
		return LevelInfo
	case "warn", "WARN", "warning":
		return LevelWarn
	case "error", "ERROR", "err":
		return LevelError
	case "fatal", "FATAL":
		return LevelFatal
	case "panic", "PANIC":
		return LevelPanic
	default:
		return LevelInfo
	}
}

// ============================================================================
// Entry
// ============================================================================

// Entry represents a single log entry
type Entry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
	Func      string                 `json:"func,omitempty"`
}

// ============================================================================
// Logger
// ============================================================================

// Logger provides structured logging capabilities
type Logger struct {
	mu       sync.RWMutex
	output   io.Writer
	level    Level
	format   Format
	fields   map[string]interface{}
	timeFunc func() time.Time
	color    bool
}

// New creates a new Logger with default settings
func New(opts ...Option) *Logger {
	logger := &Logger{
		output:   os.Stdout,
		level:    LevelInfo,
		format:   FormatJSON,
		fields:   make(map[string]interface{}),
		timeFunc: time.Now,
		color:    false,
	}
	for _, opt := range opts {
		opt(logger)
	}
	return logger
}

// NewWithOutput creates a logger with a specific output writer
func NewWithOutput(w io.Writer) *Logger {
	return &Logger{
		output:   w,
		level:    LevelInfo,
		format:   FormatJSON,
		fields:   make(map[string]interface{}),
		timeFunc: time.Now,
		color:    false,
	}
}

// ============================================================================
// Configuration
// ============================================================================

// Config holds logger configuration
type Config struct {
	Level      string
	Format     string
	OutputPath string
	TimeFormat string
}

// Option applies a configuration option
type Option func(*Logger)

// WithLevel sets the minimum log level
func WithLevel(level Level) Option {
	return func(l *Logger) {
		l.level = level
	}
}

// WithLevelString sets the minimum log level from a string
func WithLevelString(level string) Option {
	return func(l *Logger) {
		l.level = ParseLevel(level)
	}
}

// WithFormat sets the output format
func WithFormat(format Format) Option {
	return func(l *Logger) {
		l.format = format
	}
}

// WithOutput sets the output writer
func WithOutput(w io.Writer) Option {
	return func(l *Logger) {
		l.output = w
	}
}

// WithFields adds default fields to all log entries
func WithFields(fields map[string]interface{}) Option {
	return func(l *Logger) {
		for k, v := range fields {
			l.fields[k] = v
		}
	}
}

// WithField adds a single default field
func WithField(key string, value interface{}) Option {
	return func(l *Logger) {
		l.fields[key] = value
	}
}

// WithTimeFunc sets the time function
func WithTimeFunc(f func() time.Time) Option {
	return func(l *Logger) {
		l.timeFunc = f
	}
}

// ============================================================================
// Logging Methods
// ============================================================================

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	l.log(LevelDebug, msg, fields...)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	l.log(LevelInfo, msg, fields...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	l.log(LevelWarn, msg, fields...)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	l.log(LevelError, msg, fields...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, fields ...map[string]interface{}) {
	l.log(LevelFatal, msg, fields...)
	os.Exit(1)
}

// Panic logs a panic message and panics
func (l *Logger) Panic(msg string, fields ...map[string]interface{}) {
	l.log(LevelPanic, msg, fields...)
	panic(msg)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(LevelDebug, fmt.Sprintf(format, args...))
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(LevelInfo, fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(LevelWarn, fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(LevelError, fmt.Sprintf(format, args...))
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(LevelFatal, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// WithContext returns a new logger with additional fields
func (l *Logger) WithContext(fields map[string]interface{}) *Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	newFields := make(map[string]interface{})
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}

	return &Logger{
		output:   l.output,
		level:    l.level,
		format:   l.format,
		fields:   newFields,
		timeFunc: l.timeFunc,
		color:    l.color,
	}
}

// WithField returns a new logger with an additional field
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return l.WithContext(map[string]interface{}{key: value})
}

// ============================================================================
// Internal Logging
// ============================================================================

func (l *Logger) log(level Level, msg string, fields ...map[string]interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if level < l.level {
		return
	}

	// Get caller information
	pc, file, line, ok := runtime.Caller(2)
	caller := ""
	funcName := ""
	if ok {
		caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
		funcName = runtime.FuncForPC(pc).Name()
	}

	// Merge fields
	allFields := make(map[string]interface{})
	for k, v := range l.fields {
		allFields[k] = v
	}
	for _, f := range fields {
		for k, v := range f {
			allFields[k] = v
		}
	}

	entry := Entry{
		Timestamp: l.timeFunc(),
		Level:     level.String(),
		Message:   msg,
		Fields:    allFields,
		Caller:    caller,
		Func:      funcName,
	}

	// Write entry
	var data []byte
	var err error

	switch l.format {
	case FormatJSON:
		data, err = json.Marshal(entry)
	case FormatText:
		data, err = l.formatText(&entry)
	default:
		data, err = json.Marshal(entry)
	}

	if err != nil {
		fmt.Fprintf(l.output, `{"error":"failed to marshal log entry","msg":"%s"}`+"\n", msg)
		return
	}

	l.output.Write(data)
	l.output.Write([]byte("\n"))
}

func (l *Logger) formatText(entry *Entry) ([]byte, error) {
	// Format: 2025-01-01T00:00:00Z LEVEL message field1=value1 field2=value2
	timestamp := entry.Timestamp.Format(time.RFC3339)

	fields := ""
	for k, v := range entry.Fields {
		fields += fmt.Sprintf(" %s=%v", k, v)
	}

	if entry.Caller != "" {
		fields += fmt.Sprintf(" caller=%s", entry.Caller)
	}

	return []byte(fmt.Sprintf("%s %s %s%s\n", timestamp, entry.Level, entry.Message, fields)), nil
}

// ============================================================================
// Global Logger
// ============================================================================

var (
	globalMu     sync.RWMutex
	globalLogger *Logger
)

// Default returns the global logger
func Default() *Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	if globalLogger == nil {
		globalLogger = New()
	}
	return globalLogger
}

// SetDefault sets the global logger
func SetDefault(l *Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = l
}

// Configure applies configuration to the global logger
func Configure(opts ...Option) {
	l := Default()
	for _, opt := range opts {
		opt(l)
	}
}

// Global convenience functions
func Debug(msg string, fields ...map[string]interface{}) { Default().Debug(msg, fields...) }
func Info(msg string, fields ...map[string]interface{})  { Default().Info(msg, fields...) }
func Warn(msg string, fields ...map[string]interface{})  { Default().Warn(msg, fields...) }
func Error(msg string, fields ...map[string]interface{}) { Default().Error(msg, fields...) }
func Fatal(msg string, fields ...map[string]interface{}) { Default().Fatal(msg, fields...) }
func Panic(msg string, fields ...map[string]interface{}) { Default().Panic(msg, fields...) }

func Debugf(format string, args ...interface{}) { Default().Debugf(format, args...) }
func Infof(format string, args ...interface{})  { Default().Infof(format, args...) }
func Warnf(format string, args ...interface{})  { Default().Warnf(format, args...) }
func Errorf(format string, args ...interface{}) { Default().Errorf(format, args...) }
func Fatalf(format string, args ...interface{}) { Default().Fatalf(format, args...) }
