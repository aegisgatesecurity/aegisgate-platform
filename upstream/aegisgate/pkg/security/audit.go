// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
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

type AuditEvent struct {
	Timestamp time.Time     `json:"timestamp"`
	EventType EventType     `json:"event_type"`
	Severity  Severity      `json:"severity"`
	UserID    string        `json:"user_id,omitempty"`
	IPAddress string        `json:"ip_address"`
	Resource  string        `json:"resource"`
	Action    string        `json:"action"`
	Status    string        `json:"status"`
	Message   string        `json:"message"`
	Duration  time.Duration `json:"duration,omitempty"`
}

type EventType string

const (
	AuditEventAuth     EventType = "AUTH"
	AuditEventAccess   EventType = "ACCESS"
	AuditEventSecurity EventType = "SECURITY"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type AuditLogger struct {
	logger     *slog.Logger
	file       *os.File
	fileMutex  sync.Mutex
	eventTypes []EventType
	enabled    bool
}

func NewAuditLogger(enabled bool, eventTypes []EventType) *AuditLogger {
	return &AuditLogger{
		enabled:    enabled,
		eventTypes: eventTypes,
		logger:     slog.Default().WithGroup("audit"),
	}
}

func (al *AuditLogger) Log(event AuditEvent) {
	if !al.enabled {
		return
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

func AuditMiddleware(logger *AuditLogger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)
		_ = duration // use variable
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

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
