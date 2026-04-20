// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// MCP Audit Logger - Logs MCP operations for compliance and forensics
// =========================================================================

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// AuditLogger logs MCP operations
type AuditLogger struct {
	logger     *slog.Logger
	mu         sync.RWMutex
	entries    []*AuditEntry
	maxEntries int
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger *slog.Logger) *AuditLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditLogger{
		logger:     logger,
		entries:    make([]*AuditEntry, 0),
		maxEntries: 10000, // Keep last 10k entries in memory
	}
}

// Log logs an audit entry
func (l *AuditLogger) Log(ctx context.Context, entry *AuditEntry) error {
	// Generate ID if not set
	if entry.ID == "" {
		entry.ID = generateAuditID()
	}

	// Set timestamp if not set
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Store in memory
	l.mu.Lock()
	l.entries = append(l.entries, entry)
	// Trim if needed
	if len(l.entries) > l.maxEntries {
		l.entries = l.entries[len(l.entries)-l.maxEntries:]
	}
	l.mu.Unlock()

	// Log to structured logger
	l.logEntry(entry)

	return nil
}

// logEntry logs an entry to the structured logger
func (l *AuditLogger) logEntry(entry *AuditEntry) {
	attrs := []any{
		slog.String("id", entry.ID),
		slog.String("type", entry.Type),
		slog.String("connection_id", entry.ConnectionID),
		slog.String("tool_name", entry.ToolName),
		slog.Bool("allowed", entry.Allowed),
		slog.Int("risk_score", entry.RiskScore),
	}

	if entry.SessionID != "" {
		attrs = append(attrs, slog.String("session_id", truncateID(entry.SessionID)))
	}
	if entry.AgentID != "" {
		attrs = append(attrs, slog.String("agent_id", truncateID(entry.AgentID)))
	}
	if entry.AgentRole != "" {
		attrs = append(attrs, slog.String("agent_role", entry.AgentRole))
	}
	if entry.Error != "" {
		attrs = append(attrs, slog.String("error", entry.Error))
	}
	if entry.Duration > 0 {
		attrs = append(attrs, slog.Duration("duration", entry.Duration))
	}

	switch entry.Type {
	case "tool_denied":
		l.logger.Warn("MCP tool denied", attrs...)
	case "tool_error":
		l.logger.Error("MCP tool error", attrs...)
	case "initialize":
		l.logger.Info("MCP client initialized", attrs...)
	default:
		l.logger.Debug("MCP audit", attrs...)
	}
}

// LogInitialize logs an MCP initialization
func (l *AuditLogger) LogInitialize(ctx context.Context, connID string, clientInfo *ClientInfo) {
	l.Log(ctx, &AuditEntry{
		Type:         "initialize",
		ConnectionID: connID,
		ClientInfo:   clientInfo,
	})
}

// LogToolCall logs a tool call attempt
func (l *AuditLogger) LogToolCall(ctx context.Context, connID, sessionID, agentID, toolName string, params map[string]interface{}) {
	l.Log(ctx, &AuditEntry{
		Type:         "tool_call",
		ConnectionID: connID,
		SessionID:    sessionID,
		AgentID:      agentID,
		ToolName:     toolName,
		Parameters:   params,
	})
}

// LogToolAllowed logs an allowed tool call
func (l *AuditLogger) LogToolAllowed(ctx context.Context, entry *AuditEntry) {
	entry.Type = "tool_allowed"
	entry.Allowed = true
	l.Log(ctx, entry)
}

// LogToolDenied logs a denied tool call
func (l *AuditLogger) LogToolDenied(ctx context.Context, entry *AuditEntry, reason string) {
	entry.Type = "tool_denied"
	entry.Allowed = false
	entry.Error = reason
	entry.RiskScore = 80 // High risk for denied calls
	l.Log(ctx, entry)
}

// LogToolSuccess logs a successful tool execution
func (l *AuditLogger) LogToolSuccess(ctx context.Context, entry *AuditEntry, result string, duration time.Duration) {
	entry.Type = "tool_success"
	entry.Allowed = true
	entry.Result = truncateResult(result)
	entry.Duration = duration
	l.Log(ctx, entry)
}

// LogToolError logs a tool execution error
func (l *AuditLogger) LogToolError(ctx context.Context, entry *AuditEntry, err error, duration time.Duration) {
	entry.Type = "tool_error"
	entry.Allowed = false
	entry.Error = err.Error()
	entry.Duration = duration
	l.Log(ctx, entry)
}

// LogConnectionOpened logs a new MCP connection
func (l *AuditLogger) LogConnectionOpened(ctx context.Context, connID string) {
	l.Log(ctx, &AuditEntry{
		Type:         "connection_open",
		ConnectionID: connID,
	})
}

// LogConnectionClosed logs a closed MCP connection
func (l *AuditLogger) LogConnectionClosed(ctx context.Context, connID string, reason string) {
	entry := &AuditEntry{
		Type:         "connection_close",
		ConnectionID: connID,
	}
	if reason != "" {
		entry.Error = reason
	}
	l.Log(ctx, entry)
}

// GetEntries returns recent audit entries
func (l *AuditLogger) GetEntries(limit int) []*AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if limit <= 0 || limit > len(l.entries) {
		limit = len(l.entries)
	}

	// Return most recent first
	result := make([]*AuditEntry, limit)
	for i := 0; i < limit; i++ {
		result[i] = l.entries[len(l.entries)-limit+i]
	}
	return result
}

// GetEntriesByType returns entries filtered by type
func (l *AuditLogger) GetEntriesByType(entryType string, limit int) []*AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []*AuditEntry
	for i := len(l.entries) - 1; i >= 0 && len(result) < limit; i-- {
		if l.entries[i].Type == entryType {
			result = append(result, l.entries[i])
		}
	}
	return result
}

// GetEntriesBySession returns entries for a specific session
func (l *AuditLogger) GetEntriesBySession(sessionID string, limit int) []*AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []*AuditEntry
	for i := len(l.entries) - 1; i >= 0 && len(result) < limit; i-- {
		if l.entries[i].SessionID == sessionID {
			result = append(result, l.entries[i])
		}
	}
	return result
}

// GetEntriesByAgent returns entries for a specific agent
func (l *AuditLogger) GetEntriesByAgent(agentID string, limit int) []*AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []*AuditEntry
	for i := len(l.entries) - 1; i >= 0 && len(result) < limit; i-- {
		if l.entries[i].AgentID == agentID {
			result = append(result, l.entries[i])
		}
	}
	return result
}

// GetDeniedEntries returns all denied tool calls
func (l *AuditLogger) GetDeniedEntries(limit int) []*AuditEntry {
	return l.GetEntriesByType("tool_denied", limit)
}

// ExportJSON exports all entries as JSON
func (l *AuditLogger) ExportJSON() ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return json.MarshalIndent(l.entries, "", "  ")
}

// GetStats returns audit statistics
func (l *AuditLogger) GetStats() *AuditStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := &AuditStats{
		TotalEntries: len(l.entries),
	}

	for _, entry := range l.entries {
		switch entry.Type {
		case "tool_allowed":
			stats.AllowedCalls++
		case "tool_denied":
			stats.DeniedCalls++
		case "tool_error":
			stats.ErrorCalls++
		case "initialize":
			stats.InitCount++
		case "connection_open":
			stats.Connections++
		}
	}

	return stats
}

// AuditStats contains audit statistics
type AuditStats struct {
	TotalEntries int `json:"total_entries"`
	AllowedCalls int `json:"allowed_calls"`
	DeniedCalls  int `json:"denied_calls"`
	ErrorCalls   int `json:"error_calls"`
	InitCount    int `json:"init_count"`
	Connections  int `json:"connections"`
}

// Helper functions
func generateAuditID() string {
	return fmt.Sprintf("audit-%d-%s", time.Now().UnixNano()%1000000, randomString(8))
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

func truncateResult(result string) string {
	if len(result) > 500 {
		return result[:500] + "... (truncated)"
	}
	return result
}

func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12] + "..."
	}
	return id
}

// Compile-time interface check
var _ = (&AuditLogger{}).Log

// =============================================================================
// TYPES - These types are used by AuditLogger
// =============================================================================

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Timestamp    time.Time              `json:"timestamp"`
	ConnectionID string                 `json:"connection_id"`
	SessionID    string                 `json:"session_id,omitempty"`
	AgentID      string                 `json:"agent_id,omitempty"`
	AgentName    string                 `json:"agent_name,omitempty"`
	AgentRole    string                 `json:"agent_role,omitempty"`
	ToolName     string                 `json:"tool_name,omitempty"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	Result       string                 `json:"result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	RiskScore    int                    `json:"risk_score"`
	Duration     time.Duration          `json:"duration"`
	Allowed      bool                   `json:"allowed"`
	ClientInfo   *ClientInfo            `json:"client_info,omitempty"`
}
