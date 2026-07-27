package unifiedaudit

import (
	"context"
	"time"
)

// Logger defines the interface for unified audit logging.
type Logger interface {
	Log(ctx context.Context, event *AuditEvent) error
}

// UnifiedAuditLogger implements unified audit logging.
type UnifiedAuditLogger struct {
	storage AuditStorage
}

// AuditStorage defines the interface for storing audit events.
type AuditStorage interface {
	StoreEvent(ctx context.Context, event *AuditEvent) error
}

// NewUnifiedAuditLogger creates a new UnifiedAuditLogger.
func NewUnifiedAuditLogger(storage AuditStorage) *UnifiedAuditLogger {
	return &UnifiedAuditLogger{
		storage: storage,
	}
}

// Log logs a unified audit event.
func (l *UnifiedAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	event.EventID = generateEventID()
	event.Timestamp = time.Now()
	return l.storage.StoreEvent(ctx, event)
}

// generateEventID generates a unique event ID.
func generateEventID() string {
	return "event-" + time.Now().Format("20060102-150405.999999999")
}
