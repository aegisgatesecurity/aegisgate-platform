// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security (adapted from AegisGate Security)
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package security

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// AuditEvent represents a security audit event
type AuditEvent struct {
	Timestamp time.Time     `json:"timestamp"`
	EventType EventType     `json:"event_type"`
	Severity  Severity      `json:"severity"`
	UserID    string        `json:"user_id,omitempty"`
	AgentID   string        `json:"agent_id,omitempty"`
	IPAddress string        `json:"ip_address"`
	Resource  string        `json:"resource"`
	Action    string        `json:"action"`
	Status    string        `json:"status"`
	Message   string        `json:"message"`
	Duration  time.Duration `json:"duration,omitempty"`
	ToolName  string        `json:"tool_name,omitempty"`
	SessionID string        `json:"session_id,omitempty"`
}

// EventType categorizes audit events
type EventType string

const (
	AuditEventAuth     EventType = "AUTH"
	AuditEventAccess   EventType = "ACCESS"
	AuditEventSecurity EventType = "SECURITY"
	AuditEventTool     EventType = "TOOL"
	AuditEventSession  EventType = "SESSION"
)

// Severity represents the severity level of an audit event
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// AuditLogger provides audit logging capabilities
type AuditLogger struct {
	logger     *slog.Logger
	file       *os.File
	fileMutex  sync.Mutex
	eventTypes []EventType
	enabled    bool
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(enabled bool, eventTypes []EventType) *AuditLogger {
	return &AuditLogger{
		enabled:    enabled,
		eventTypes: eventTypes,
		logger:     slog.Default().WithGroup("audit"),
	}
}

// SetOutputFile sets the file for audit logging
func (al *AuditLogger) SetOutputFile(path string) error {
	if path == "" {
		al.file = nil
		return nil
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	al.file = file
	return nil
}

// Log writes an audit event
func (al *AuditLogger) Log(event AuditEvent) {
	if !al.enabled {
		return
	}

	// Filter by event type if specified
	if len(al.eventTypes) > 0 {
		found := false
		for _, et := range al.eventTypes {
			if et == event.EventType {
				found = true
				break
			}
		}
		if !found {
			return
		}
	}

	event.Timestamp = time.Now().UTC()
	data, _ := json.Marshal(event)
	al.logger.Info("audit_event", "data", string(data))

	if al.file != nil {
		al.fileMutex.Lock()
		defer al.fileMutex.Unlock()
		if _, err := al.file.Write(data); err != nil {
			al.logger.Error("failed to write audit log", "error", err)
		}
		if _, err := al.file.Write([]byte{10}); err != nil {
			al.logger.Error("failed to write audit log newline", "error", err)
		}
	}
}

// LogAgentToolCall logs a tool call from an agent
func (al *AuditLogger) LogAgentToolCall(agentID, sessionID, toolName, status, message string) {
	al.Log(AuditEvent{
		EventType: AuditEventTool,
		Severity:  getSeverityFromStatus(status),
		AgentID:   agentID,
		SessionID: sessionID,
		ToolName:  toolName,
		Action:    "execute",
		Status:    status,
		Message:   message,
	})
}

// LogSessionEvent logs a session event
func (al *AuditLogger) LogSessionEvent(agentID, sessionID, action, status, message string) {
	al.Log(AuditEvent{
		EventType: AuditEventSession,
		Severity:  getSeverityFromStatus(status),
		AgentID:   agentID,
		SessionID: sessionID,
		Action:    action,
		Status:    status,
		Message:   message,
	})
}

// LogSecurityEvent logs a security event
func (al *AuditLogger) LogSecurityEvent(agentID, sessionID, action, severity, message string) {
	al.Log(AuditEvent{
		EventType: AuditEventSecurity,
		Severity:  Severity(severity),
		AgentID:   agentID,
		SessionID: sessionID,
		Action:    action,
		Status:    "blocked",
		Message:   message,
	})
}

// Close closes the audit logger and any open files
func (al *AuditLogger) Close() error {
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

// getSeverityFromStatus determines severity from status
func getSeverityFromStatus(status string) Severity {
	switch status {
	case "blocked", "denied", "error":
		return SeverityWarning
	case "critical", "denied_high_risk":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// AuditResponseWriter wraps an http.ResponseWriter to capture response status
type AuditResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (arw *AuditResponseWriter) WriteHeader(code int) {
	arw.statusCode = code
	arw.ResponseWriter.WriteHeader(code)
}

func (arw *AuditResponseWriter) Write(b []byte) (int, error) {
	n, err := arw.ResponseWriter.Write(b)
	arw.bytesWritten += n
	return n, err
}

// AuditMiddleware creates middleware for HTTP request auditing
func AuditMiddleware(logger *AuditLogger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &AuditResponseWriter{ResponseWriter: w, statusCode: 200}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		logger.Log(AuditEvent{
			EventType: AuditEventAccess,
			Severity:  SeverityInfo,
			IPAddress: r.RemoteAddr,
			Resource:  r.URL.Path,
			Action:    r.Method,
			Status:    http.StatusText(rw.statusCode),
			Duration:  duration,
		})
	})
}
