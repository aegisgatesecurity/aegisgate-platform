// SPDX-FileCopyrightText: Copyright (C) 2025 AegisGuard Security
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// ============================================================================
// Format Types
// ============================================================================

// Format represents the output format
type Format string

const (
	FormatJSON  Format = "json"
	FormatText  Format = "text"
	FormatPlain Format = "plain"
)

// ============================================================================
// JSON Formatter
// ============================================================================

// JSONFormatter formats log entries as JSON
type JSONFormatter struct {
	TimestampFormat string
	TimestampKey    string
	LevelKey        string
	MessageKey      string
	CallerKey       string
	FuncKey         string
	FieldsKey       string
}

// NewJSONFormatter creates a new JSON formatter with defaults
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{
		TimestampFormat: time.RFC3339,
		TimestampKey:    "timestamp",
		LevelKey:        "level",
		MessageKey:      "message",
		CallerKey:       "caller",
		FuncKey:         "func",
		FieldsKey:       "fields",
	}
}

// Format formats an entry as JSON
func (f *JSONFormatter) Format(entry *Entry) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)

	obj := make(map[string]interface{})
	obj[f.TimestampKey] = entry.Timestamp.Format(f.TimestampFormat)
	obj[f.LevelKey] = entry.Level
	obj[f.MessageKey] = entry.Message

	if entry.Caller != "" {
		obj[f.CallerKey] = entry.Caller
	}
	if entry.Func != "" {
		obj[f.FuncKey] = entry.Func
	}
	if len(entry.Fields) > 0 {
		obj[f.FieldsKey] = entry.Fields
	}

	err := enc.Encode(obj)
	return buf.Bytes(), err
}

// ============================================================================
// Text Formatter
// ============================================================================

// TextFormatter formats log entries as human-readable text
type TextFormatter struct {
	TimestampFormat string
	TimestampColor  bool
	LevelColor      bool
	Colorize        bool
}

// NewTextFormatter creates a new text formatter
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		TimestampColor:  false,
		LevelColor:      false,
		Colorize:        false,
	}
}

// Format formats an entry as text
func (f *TextFormatter) Format(entry *Entry) ([]byte, error) {
	var buf bytes.Buffer

	// Timestamp
	buf.WriteString(entry.Timestamp.Format(f.TimestampFormat))
	buf.WriteString(" ")

	// Level
	level := f.colorizeLevel(entry.Level)
	buf.WriteString(level)
	buf.WriteString(" ")

	// Message
	buf.WriteString(entry.Message)

	// Fields
	if len(entry.Fields) > 0 {
		buf.WriteString(" {")
		first := true
		for k, v := range entry.Fields {
			if !first {
				buf.WriteString(", ")
			}
			buf.WriteString(k)
			buf.WriteString("=")
			buf.WriteString(formatValue(v))
			first = false
		}
		buf.WriteString("}")
	}

	// Caller
	if entry.Caller != "" {
		buf.WriteString(" [")
		buf.WriteString(entry.Caller)
		buf.WriteString("]")
	}

	buf.WriteString("\n")
	return buf.Bytes(), nil
}

func (f *TextFormatter) colorizeLevel(level string) string {
	if !f.Colorize {
		return level
	}
	switch level {
	case "DEBUG":
		return colorDarkGray + level + colorReset
	case "INFO":
		return colorCyan + level + colorReset
	case "WARN":
		return colorYellow + level + colorReset
	case "ERROR":
		return colorRed + level + colorReset
	case "FATAL":
		return colorRed + colorBold + level + colorReset
	case "PANIC":
		return colorMagenta + colorBold + level + colorReset
	default:
		return level
	}
}

// ANSI color codes
const (
	colorReset    = "\033[0m"
	colorBold     = "\033[1m"
	colorRed      = "\033[31m"
	colorGreen    = "\033[32m"
	colorYellow   = "\033[33m"
	colorBlue     = "\033[34m"
	colorMagenta  = "\033[35m"
	colorCyan     = "\033[36m"
	colorGray     = "\033[90m"
	colorDarkGray = "\033[90m"
)

// ============================================================================
// Plain Formatter
// ============================================================================

// PlainFormatter formats log entries with minimal formatting
type PlainFormatter struct {
	TimestampFormat string
	IncludeLevel    bool
	IncludeCaller   bool
}

// NewPlainFormatter creates a new plain formatter
func NewPlainFormatter() *PlainFormatter {
	return &PlainFormatter{
		TimestampFormat: "15:04:05",
		IncludeLevel:    true,
		IncludeCaller:   false,
	}
}

// Format formats an entry as plain text
func (f *PlainFormatter) Format(entry *Entry) ([]byte, error) {
	var buf bytes.Buffer

	// Timestamp
	buf.WriteString(entry.Timestamp.Format(f.TimestampFormat))
	buf.WriteString(" ")

	// Level
	if f.IncludeLevel {
		buf.WriteString("[")
		buf.WriteString(entry.Level)
		buf.WriteString("] ")
	}

	// Message
	buf.WriteString(entry.Message)

	// Fields
	if len(entry.Fields) > 0 {
		for k, v := range entry.Fields {
			buf.WriteString(" ")
			buf.WriteString(k)
			buf.WriteString("=")
			buf.WriteString(formatValue(v))
		}
	}

	// Caller
	if f.IncludeCaller && entry.Caller != "" {
		buf.WriteString(" (")
		buf.WriteString(entry.Caller)
		buf.WriteString(")")
	}

	buf.WriteString("\n")
	return buf.Bytes(), nil
}

// ============================================================================
// Helpers
// ============================================================================

// formatValue formats a value for text output
func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		if needsQuotes(val) {
			return `"` + val + `"`
		}
		return val
	case []byte:
		return string(val)
	default:
		return formatInterface(val)
	}
}

// needsQuotes determines if a string needs quoting
func needsQuotes(s string) bool {
	if s == "" {
		return true
	}
	for _, c := range s {
		if c == ' ' || c == '=' || c == ',' || c == '"' {
			return true
		}
	}
	return false
}

// formatInterface formats an interface value
func formatInterface(v interface{}) string {
	switch val := v.(type) {
	case int, int8, int16, int32, int64:
		return strings.TrimSuffix(strings.TrimPrefix(formatInt(val), "%!"), "P")
	case uint, uint8, uint16, uint32, uint64:
		return formatUint(val)
	case float32, float64:
		return formatFloat(val)
	case bool:
		return strings.ToUpper(strings.TrimPrefix(formatBool(val), "%!"))
	case error:
		return val.Error()
	default:
		data, err := json.Marshal(val)
		if err != nil {
			return "<error>"
		}
		return string(data)
	}
}

// Placeholder implementations (simplified)
func formatInt(v interface{}) string {
	switch val := v.(type) {
	case int:
		return string(rune(val + '0')) // Simplified
	case int64:
		return "0"
	}
	return "0"
}

func formatUint(v interface{}) string {
	return "0"
}

func formatFloat(v interface{}) string {
	return "0.0"
}

func formatBool(v interface{}) string {
	if v.(bool) {
		return "true"
	}
	return "false"
}
