// Package audit - Audit logging for AI agent actions
// Provides comprehensive logging for compliance and security auditing
package audit

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Logger provides audit logging functionality
type Logger struct {
	mu         sync.RWMutex
	output     *os.File
	encoder    *json.Encoder
	entries    []Action      // In-memory log storage
	maxEntries int           // Maximum entries to retain (0 = unlimited)
	retention  time.Duration // Log retention period (0 = forever)
}

// QueryFilter for filtering audit logs
type QueryFilter struct {
	SessionID  string
	AgentID    string
	ToolName   string
	ActionType string
	Allowed    *bool
	FromTime   *time.Time
	ToTime     *time.Time
	RiskAbove  int
}

// Action represents an auditable action
type Action struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // "tool_call", "session_start", "policy_denial", etc.
	Timestamp   time.Time              `json:"timestamp"`
	SessionID   string                 `json:"session_id"`
	AgentID     string                 `json:"agent_id"`
	ToolName    string                 `json:"tool_name,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Allowed     bool                   `json:"allowed"`
	Reason      string                 `json:"reason,omitempty"`
	RiskScore   int                    `json:"risk_score,omitempty"`
	PolicyMatch []string               `json:"policy_match,omitempty"`
	Duration    time.Duration          `json:"duration,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewLogger creates a new audit logger
func NewLogger() *Logger {
	return &Logger{
		output:     os.Stdout,
		encoder:    json.NewEncoder(os.Stdout),
		entries:    make([]Action, 0),
		maxEntries: 10000,
		retention:  30 * 24 * time.Hour, // 30 days default
	}
}

// NewLoggerWithConfig creates a logger with custom configuration
func NewLoggerWithConfig(maxEntries int, retention time.Duration) *Logger {
	logger := NewLogger()
	logger.maxEntries = maxEntries
	logger.retention = retention
	if maxEntries > 0 {
		logger.entries = make([]Action, 0, maxEntries)
	}
	return logger
}

// LogAction logs an action to the audit trail
func (l *Logger) LogAction(ctx context.Context, action *Action) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if action.ID == "" {
		action.ID = generateActionID()
	}
	if action.Timestamp.IsZero() {
		action.Timestamp = time.Now()
	}

	// Store entry in memory
	l.entries = append(l.entries, *action)

	// Trim if exceeds max entries
	if l.maxEntries > 0 && len(l.entries) > l.maxEntries {
		l.entries = l.entries[len(l.entries)-l.maxEntries:]
	}

	// Also output to configured writer
	return l.encoder.Encode(action)
}

// Query returns entries matching the filter
func (l *Logger) Query(filter *QueryFilter) []Action {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]Action, 0)
	now := time.Now()

	for _, entry := range l.entries {
		// Check retention
		if l.retention > 0 && now.Sub(entry.Timestamp) > l.retention {
			continue
		}

		// Apply filters
		if filter.SessionID != "" && entry.SessionID != filter.SessionID {
			continue
		}
		if filter.AgentID != "" && entry.AgentID != filter.AgentID {
			continue
		}
		if filter.ToolName != "" && entry.ToolName != filter.ToolName {
			continue
		}
		if filter.ActionType != "" && entry.Type != filter.ActionType {
			continue
		}
		if filter.Allowed != nil && entry.Allowed != *filter.Allowed {
			continue
		}
		if filter.FromTime != nil && entry.Timestamp.Before(*filter.FromTime) {
			continue
		}
		if filter.ToTime != nil && entry.Timestamp.After(*filter.ToTime) {
			continue
		}
		if filter.RiskAbove > 0 && entry.RiskScore < filter.RiskAbove {
			continue
		}

		result = append(result, entry)
	}

	return result
}

// GetEntries returns all stored entries
func (l *Logger) GetEntries() []Action {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]Action, len(l.entries))
	copy(result, l.entries)
	return result
}

// GetEntryCount returns the number of stored entries
func (l *Logger) GetEntryCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// Clear removes all entries
func (l *Logger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = make([]Action, 0)
}

// Cleanup removes expired entries based on retention policy
func (l *Logger) Cleanup() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.retention == 0 {
		return 0 // No retention limit
	}

	now := time.Now()
	cutoff := now.Add(-l.retention)

	original := len(l.entries)
	l.entries = filterExpiredEntries(l.entries, cutoff)
	return original - len(l.entries)
}

// filterExpiredEntries removes entries older than cutoff
func filterExpiredEntries(entries []Action, cutoff time.Time) []Action {
	result := make([]Action, 0)
	for _, e := range entries {
		if e.Timestamp.After(cutoff) {
			result = append(result, e)
		}
	}
	return result
}

// LogSessionStart logs the start of an agent session
func (l *Logger) LogSessionStart(ctx context.Context, sessionID, agentID string) error {
	return l.LogAction(ctx, &Action{
		Type:      "session_start",
		SessionID: sessionID,
		AgentID:   agentID,
		Allowed:   true,
	})
}

// LogSessionEnd logs the end of an agent session
func (l *Logger) LogSessionEnd(ctx context.Context, sessionID, agentID string) error {
	return l.LogAction(ctx, &Action{
		Type:      "session_end",
		SessionID: sessionID,
		AgentID:   agentID,
		Allowed:   true,
	})
}

// LogToolCall logs a tool call attempt
func (l *Logger) LogToolCall(ctx context.Context, toolName, sessionID string, allowed bool, reason string) error {
	return l.LogAction(ctx, &Action{
		Type:      "tool_call",
		ToolName:  toolName,
		SessionID: sessionID,
		Allowed:   allowed,
		Reason:    reason,
	})
}

// LogPolicyDenial logs a policy denial
func (l *Logger) LogPolicyDenial(ctx context.Context, sessionID, toolName, reason string) error {
	return l.LogAction(ctx, &Action{
		Type:      "policy_denial",
		ToolName:  toolName,
		SessionID: sessionID,
		Allowed:   false,
		Reason:    reason,
	})
}

// LogRiskAlert logs a high-risk action
func (l *Logger) LogRiskAlert(ctx context.Context, sessionID, toolName string, riskScore int) error {
	return l.LogAction(ctx, &Action{
		Type:      "risk_alert",
		ToolName:  toolName,
		SessionID: sessionID,
		Allowed:   false,
		RiskScore: riskScore,
		Reason:    "Risk score exceeded threshold",
	})
}

// Close closes the audit logger
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Could flush to file, close connections, etc.
	return nil
}

// generateActionID creates a unique action ID
func generateActionID() string {
	return "act_" + time.Now().Format("20060102150405.000000000")
}

// Formatter provides custom audit log formatting
type Formatter struct {
	format string // "json", "csv", "text"
}

// NewFormatter creates a new formatter
func NewFormatter(format string) *Formatter {
	return &Formatter{format: format}
}

// FormatAction formats an action for output
func (f *Formatter) FormatAction(action *Action) ([]byte, error) {
	switch f.format {
	case "json":
		return json.Marshal(action)
	case "csv":
		return formatCSV(action)
	default:
		return json.Marshal(action)
	}
}

// formatCSV formats an action as CSV
func formatCSV(action *Action) ([]byte, error) {
	// Simple CSV format
	csv := struct {
		ID, Type, Timestamp, SessionID, AgentID, ToolName, Allowed, Reason string
	}{
		action.ID,
		action.Type,
		action.Timestamp.Format(time.RFC3339),
		action.SessionID,
		action.AgentID,
		action.ToolName,
		boolToString(action.Allowed),
		action.Reason,
	}

	// Return JSON for now (CSV implementation would be more complex)
	return json.Marshal(csv)
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Exporter exports audit logs to external systems
type Exporter struct {
	target string // "file", "syslog", "elasticsearch", etc.
	format string
}

// NewExporter creates a new exporter
func NewExporter(target, format string) *Exporter {
	return &Exporter{
		target: target,
		format: format,
	}
}

// Export sends audit logs to the target
func (e *Exporter) Export(action *Action) error {
	// TODO: Implement actual export to various targets
	switch e.target {
	case "file":
		// Write to file
	case "syslog":
		// Send to syslog
	case "elasticsearch":
		// Send to ES
	}
	return nil
}
