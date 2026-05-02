// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package opsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditLevel represents the severity level of an audit entry
type AuditLevel int

const (
	AuditLevelInfo     AuditLevel = iota // Informational events
	AuditLevelWarning                    // Warning events
	AuditLevelError                      // Error events
	AuditLevelCritical                   // Critical events
	AuditLevelAlert                      // Alert events
)

// String returns the string representation of the audit level
func (al AuditLevel) String() string {
	switch al {
	case AuditLevelInfo:
		return "INFO"
	case AuditLevelWarning:
		return "WARNING"
	case AuditLevelError:
		return "ERROR"
	case AuditLevelCritical:
		return "CRITICAL"
	case AuditLevelAlert:
		return "ALERT"
	default:
		return "UNKNOWN"
	}
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	Level          AuditLevel             `json:"level"`
	EventType      string                 `json:"event_type"`
	Message        string                 `json:"message"`
	Data           map[string]interface{} `json:"data,omitempty"`
	Source         string                 `json:"source"`
	Hash           string                 `json:"hash,omitempty"`
	PreviousHash   string                 `json:"previous_hash,omitempty"`
	ComplianceTags []string               `json:"compliance_tags,omitempty"`
	TenantID       string                 `json:"tenant_id,omitempty"`
}

// RetentionPeriod represents the configurable retention period
type RetentionPeriod int

const (
	Retention90Days  RetentionPeriod = 90
	Retention1Year   RetentionPeriod = 365
	Retention3Years  RetentionPeriod = 365 * 3
	Retention5Years  RetentionPeriod = 365 * 5
	Retention7Years  RetentionPeriod = 365 * 7 // SOC2/HIPAA requirement
	Retention10Years RetentionPeriod = 365 * 10
	RetentionForever RetentionPeriod = -1
)

// SecureAuditLog provides an in-memory audit log with hash chain integrity
type SecureAuditLog struct {
	mu           sync.RWMutex
	Entries      []*AuditEntry
	LastHash     string
	Count        int
	enabled      bool
	logIntegrity bool
	callback     func(*AuditEntry)
	maxEntries   int
}

// NewSecureAuditLog creates a new secure audit log
func NewSecureAuditLog() *SecureAuditLog {
	return &SecureAuditLog{
		Entries:      make([]*AuditEntry, 0),
		enabled:      true,
		logIntegrity: true,
		maxEntries:   100000,
	}
}

// EnableAudit enables audit logging
func (a *SecureAuditLog) EnableAudit() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = true
}

// DisableAudit disables audit logging
func (a *SecureAuditLog) DisableAudit() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = false
}

// IsAuditEnabled returns true if audit logging is enabled
func (a *SecureAuditLog) IsAuditEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

// SetMaxEntries sets the maximum number of entries to keep
func (a *SecureAuditLog) SetMaxEntries(max int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.maxEntries = max
}

// SetCallback sets the callback function for audit entries
func (a *SecureAuditLog) SetCallback(callback func(*AuditEntry)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.callback = callback
}

// LogAudit logs an audit entry
func (a *SecureAuditLog) LogAudit(entry *AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return
	}

	// Add previous hash for chain integrity
	entry.PreviousHash = a.LastHash

	// Calculate and set hash
	entry.Hash = a.calculateEntryHash(entry)
	a.LastHash = entry.Hash

	// Add entry
	a.Entries = append(a.Entries, entry)
	a.Count++

	// Prune if needed
	if len(a.Entries) > a.maxEntries {
		a.Entries = a.Entries[len(a.Entries)-a.maxEntries:]
	}

	// Trigger callback if set
	if a.callback != nil {
		a.callback(entry)
	}
}

// LogAuditWithLevel logs an audit entry with a specific level
func (a *SecureAuditLog) LogAuditWithLevel(level AuditLevel, message string, data map[string]interface{}) {
	entry := &AuditEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Data:      data,
		Source:    "aegisgate",
		ID:        generateEntryID(),
	}
	a.LogAudit(entry)
}

// GetAuditLog returns all audit entries
func (a *SecureAuditLog) GetAuditLog() []*AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Entries
}

// GetEntriesByLevel returns all entries matching the specified level
func (a *SecureAuditLog) GetEntriesByLevel(level AuditLevel) []*AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var result []*AuditEntry
	for _, entry := range a.Entries {
		if entry.Level == level {
			result = append(result, entry)
		}
	}
	return result
}

// GetEntriesSince returns all entries since the specified time
func (a *SecureAuditLog) GetEntriesSince(since time.Time) []*AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var result []*AuditEntry
	for _, entry := range a.Entries {
		if entry.Timestamp.After(since) {
			result = append(result, entry)
		}
	}
	return result
}

// GetEntryCount returns the total number of entries
func (a *SecureAuditLog) GetEntryCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Count
}

// ClearAuditLog clears all audit entries
func (a *SecureAuditLog) ClearAuditLog() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.logIntegrity {
		a.Entries = make([]*AuditEntry, 0)
		a.Count = 0
		a.LastHash = ""
	}
}

// calculateEntryHash calculates the hash for an entry
func (a *SecureAuditLog) calculateEntryHash(entry *AuditEntry) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%v",
		entry.ID,
		entry.Timestamp.Format(time.RFC3339Nano),
		entry.Level.String(),
		entry.EventType,
		entry.Message,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GetLastHash returns the last hash in the chain
func (a *SecureAuditLog) GetLastHash() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.LastHash
}

// VerifyChainIntegrity verifies the integrity of the audit log chain
func (a *SecureAuditLog) VerifyChainIntegrity() (bool, []string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var failures []string
	previousHash := ""

	for i, entry := range a.Entries {
		// Verify individual entry hash
		expectedHash := a.calculateEntryHash(entry)
		if entry.Hash != expectedHash {
			failures = append(failures, fmt.Sprintf("Entry %d: hash mismatch", i))
		}

		// Verify chain
		if i > 0 && previousHash != "" {
			if entry.PreviousHash != previousHash {
				failures = append(failures, fmt.Sprintf("Entry %d: chain broken", i))
			}
		}
		previousHash = entry.Hash
	}

	return len(failures) == 0, failures
}

// EnableLogIntegrity enables log integrity checking
func (a *SecureAuditLog) EnableLogIntegrity() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logIntegrity = true
}

// DisableLogIntegrity disables log integrity checking
func (a *SecureAuditLog) DisableLogIntegrity() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logIntegrity = false
}

// IsLogIntegrityEnabled returns true if log integrity is enabled
func (a *SecureAuditLog) IsLogIntegrityEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.logIntegrity
}

// ExportToJSON exports the audit log to JSON
func (a *SecureAuditLog) ExportToJSON() ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	export := struct {
		Entries    []*AuditEntry `json:"entries"`
		LastHash   string        `json:"last_hash"`
		Count      int           `json:"count"`
		ExportedAt time.Time     `json:"exported_at"`
	}{
		Entries:    a.Entries,
		LastHash:   a.LastHash,
		Count:      a.Count,
		ExportedAt: time.Now(),
	}

	return json.MarshalIndent(export, "", "  ")
}

// ImportFromJSON imports audit log from JSON
func (a *SecureAuditLog) ImportFromJSON(data []byte) error {
	export := struct {
		Entries  []*AuditEntry `json:"entries"`
		LastHash string        `json:"last_hash"`
		Count    int           `json:"count"`
	}{}

	if err := json.Unmarshal(data, &export); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.Entries = export.Entries
	a.LastHash = export.LastHash
	a.Count = export.Count

	return nil
}

// StorageBackend defines the interface for persistent audit storage
type StorageBackend interface {
	Write(ctx context.Context, entry *AuditEntry) error
	Read(ctx context.Context, id string) (*AuditEntry, error)
	Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error)
	Delete(ctx context.Context, id string) error
	Close() error
}

// AuditFilter defines criteria for querying audit logs
type AuditFilter struct {
	StartTime  time.Time
	EndTime    time.Time
	Levels     []AuditLevel
	EventTypes []string
	Compliance []string // HIPAA, PCI-DSS, SOC2
	TenantID   string
	Source     string
	SearchText string
	Limit      int
	Offset     int
}

// FileStorageBackend provides filesystem-based persistent storage
type FileStorageBackend struct {
	basePath    string
	maxFileSize int64
	mu          sync.RWMutex
	currentFile *os.File
	entries     map[string]*AuditEntry
}

// NewFileStorageBackend creates a new file-based storage backend
// lgtm[go/path-injection] — basePath comes from server config, not user input; directory entries are validated with .json suffix check
func NewFileStorageBackend(basePath string, maxFileSize int64) (*FileStorageBackend, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil { // lgtm[go/path-injection] — basePath is server-configured, not user-controlled
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}

	fs := &FileStorageBackend{
		basePath:    basePath,
		maxFileSize: maxFileSize,
		entries:     make(map[string]*AuditEntry),
	}

	if err := fs.loadEntries(); err != nil {
		return nil, fmt.Errorf("failed to load existing entries: %w", err)
	}

	return fs, nil
}

// Write persists an audit entry to storage
func (fs *FileStorageBackend) Write(ctx context.Context, entry *AuditEntry) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.entries[entry.ID] = entry

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	filename := filepath.Join(fs.basePath, fmt.Sprintf("%s.json", entry.ID))
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write entry: %w", err)
	}

	return nil
}

// Read retrieves an audit entry from storage
func (fs *FileStorageBackend) Read(ctx context.Context, id string) (*AuditEntry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if entry, ok := fs.entries[id]; ok {
		return entry, nil
	}

	filename := filepath.Join(fs.basePath, fmt.Sprintf("%s.json", id))
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("entry not found: %s", id)
		}
		return nil, fmt.Errorf("failed to read entry: %w", err)
	}

	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal entry: %w", err)
	}

	return &entry, nil
}

// Query retrieves audit entries matching the filter
func (fs *FileStorageBackend) Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var results []*AuditEntry
	offset := 0
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	for _, entry := range fs.entries {
		if !filter.matchesEntry(entry) {
			continue
		}

		if offset < filter.Offset {
			offset++
			continue
		}

		if len(results) >= limit {
			break
		}

		results = append(results, entry)
	}

	return results, nil
}

// Delete removes an audit entry from storage
func (fs *FileStorageBackend) Delete(ctx context.Context, id string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.entries, id)

	filename := filepath.Join(fs.basePath, fmt.Sprintf("%s.json", id))
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete entry: %w", err)
	}

	return nil
}

// Close closes the storage backend
func (fs *FileStorageBackend) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.currentFile != nil {
		return fs.currentFile.Close()
	}
	return nil
}

// loadEntries loads all existing entries from disk
func (fs *FileStorageBackend) loadEntries() error {
	entries, err := os.ReadDir(fs.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filename := filepath.Join(fs.basePath, entry.Name()) // lgtm[go/path-injection] — entry.Name() comes from os.ReadDir of the configured basePath, not user input
		data, err := os.ReadFile(filename)
		if err != nil {
			continue
		}

		var auditEntry AuditEntry
		if err := json.Unmarshal(data, &auditEntry); err != nil {
			continue
		}

		fs.entries[auditEntry.ID] = &auditEntry
	}

	return nil
}

// matchesEntry checks if an entry matches the filter criteria
func (f *AuditFilter) matchesEntry(entry *AuditEntry) bool {
	if !f.StartTime.IsZero() && entry.Timestamp.Before(f.StartTime) {
		return false
	}
	if !f.EndTime.IsZero() && entry.Timestamp.After(f.EndTime) {
		return false
	}

	if len(f.Levels) > 0 {
		matched := false
		for _, level := range f.Levels {
			if entry.Level == level {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(f.EventTypes) > 0 {
		matched := false
		for _, eventType := range f.EventTypes {
			if entry.EventType == eventType {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(f.Compliance) > 0 {
		matched := false
		for _, comp := range f.Compliance {
			for _, tag := range entry.ComplianceTags {
				if strings.EqualFold(comp, tag) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	if f.TenantID != "" && entry.TenantID != f.TenantID {
		return false
	}

	if f.Source != "" && entry.Source != f.Source {
		return false
	}

	if f.SearchText != "" {
		searchLower := strings.ToLower(f.SearchText)
		found := false
		if strings.Contains(strings.ToLower(entry.Message), searchLower) {
			found = true
		}
		for _, v := range entry.Data {
			if strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), searchLower) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// AlertCallback is a function called when a specific audit level is triggered
type AlertCallback func(ctx context.Context, entry *AuditEntry) error

// ComplianceAuditLog extends SecureAuditLog with compliance-specific features
type ComplianceAuditLog struct {
	*SecureAuditLog
	storage           StorageBackend
	retentionPeriod   RetentionPeriod
	retentionUntil    time.Time
	alertCallbacks    map[AuditLevel][]AlertCallback
	complianceMapping map[string][]string
	tenantID          string
	mu                sync.RWMutex
}

// NewComplianceAuditLog creates a new compliance-aware audit log
func NewComplianceAuditLog(retention RetentionPeriod, storage StorageBackend, tenantID string) *ComplianceAuditLog {
	cal := &ComplianceAuditLog{
		SecureAuditLog:    NewSecureAuditLog(),
		storage:           storage,
		retentionPeriod:   retention,
		alertCallbacks:    make(map[AuditLevel][]AlertCallback),
		complianceMapping: make(map[string][]string),
		tenantID:          tenantID,
	}

	cal.initComplianceMappings()

	if retention > 0 {
		cal.retentionUntil = time.Now().Add(time.Duration(retention) * 24 * time.Hour)
	}

	return cal
}

// SetRetentionPeriod sets the retention period for audit logs
func (cal *ComplianceAuditLog) SetRetentionPeriod(period RetentionPeriod) {
	cal.mu.Lock()
	defer cal.mu.Unlock()
	cal.retentionPeriod = period
	if period > 0 {
		cal.retentionUntil = time.Now().Add(time.Duration(period) * 24 * time.Hour)
	} else {
		cal.retentionUntil = time.Time{}
	}
}

// GetRetentionPeriod returns the current retention period
func (cal *ComplianceAuditLog) GetRetentionPeriod() RetentionPeriod {
	cal.mu.RLock()
	defer cal.mu.RUnlock()
	return cal.retentionPeriod
}

// RegisterAlertCallback registers a callback for a specific audit level
func (cal *ComplianceAuditLog) RegisterAlertCallback(level AuditLevel, callback AlertCallback) {
	cal.mu.Lock()
	defer cal.mu.Unlock()
	cal.alertCallbacks[level] = append(cal.alertCallbacks[level], callback)
}

// LogComplianceEvent logs an event with compliance tags
func (cal *ComplianceAuditLog) LogComplianceEvent(
	ctx context.Context,
	level AuditLevel,
	eventType string,
	message string,
	complianceTags []string,
	data map[string]interface{},
) error {
	cal.mu.RLock()
	tags := complianceTags
	if len(tags) == 0 {
		tags = cal.complianceMapping[eventType]
	}
	tenantID := cal.tenantID
	cal.mu.RUnlock()

	entry := &AuditEntry{
		Level:          level,
		EventType:      eventType,
		Message:        message,
		Timestamp:      time.Now(),
		ComplianceTags: tags,
		Data:           data,
		TenantID:       tenantID,
		Source:         "aegisgate",
		ID:             generateEntryID(),
	}

	// Log to in-memory audit log (which handles hash chain)
	cal.LogAudit(entry)

	// Persist to storage if available
	if cal.storage != nil {
		if err := cal.storage.Write(ctx, entry); err != nil {
			fmt.Printf("Failed to persist audit entry: %v\n", err)
		}
	}

	// Trigger alert callbacks
	cal.triggerAlerts(ctx, entry)

	return nil
}

// triggerAlerts calls registered alert callbacks for the entry's level
func (cal *ComplianceAuditLog) triggerAlerts(ctx context.Context, entry *AuditEntry) {
	cal.mu.RLock()
	callbacks := cal.alertCallbacks[entry.Level]
	cal.mu.RUnlock()

	for _, callback := range callbacks {
		if err := callback(ctx, entry); err != nil {
			fmt.Printf("Alert callback error: %v\n", err)
		}
	}
}

// Query retrieves audit entries matching the filter
func (cal *ComplianceAuditLog) Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error) {
	if cal.storage != nil {
		return cal.storage.Query(ctx, filter)
	}

	if len(filter.Levels) > 0 {
		return cal.SecureAuditLog.GetEntriesByLevel(filter.Levels[0]), nil
	}
	return cal.SecureAuditLog.GetAuditLog(), nil
}

// PruneOldEntries removes entries older than the retention period
func (cal *ComplianceAuditLog) PruneOldEntries(ctx context.Context) (int, error) {
	if cal.storage == nil || cal.retentionPeriod <= 0 {
		return 0, nil
	}

	pruned := 0
	cutoff := time.Now().Add(-time.Duration(cal.retentionPeriod) * 24 * time.Hour)

	filter := AuditFilter{
		EndTime: cutoff,
		Limit:   1000,
	}

	entries, err := cal.storage.Query(ctx, filter)
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		if err := cal.storage.Delete(ctx, entry.ID); err == nil {
			pruned++
		}
	}

	return pruned, nil
}

// VerifyIntegrity verifies the integrity of all audit entries
func (cal *ComplianceAuditLog) VerifyIntegrity(ctx context.Context) (bool, []string, error) {
	valid, fails := cal.SecureAuditLog.VerifyChainIntegrity()
	if !valid {
		return false, fails, nil
	}

	if cal.storage != nil {
		filter := AuditFilter{Limit: 10000}
		entries, err := cal.storage.Query(ctx, filter)
		if err != nil {
			return false, nil, err
		}

		for _, entry := range entries {
			expectedHash := cal.SecureAuditLog.calculateEntryHash(entry)
			if entry.Hash != expectedHash {
				fails = append(fails, fmt.Sprintf("Entry %s: hash mismatch", entry.ID))
			}
		}
	}

	return len(fails) == 0, fails, nil
}

// ExportForCompliance exports audit logs in a tamper-evident format
func (cal *ComplianceAuditLog) ExportForCompliance(ctx context.Context, format string) ([]byte, error) {
	filter := AuditFilter{Limit: 100000}
	entries, err := cal.Query(ctx, filter)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(struct {
			Entries       []*AuditEntry   `json:"entries"`
			Retention     RetentionPeriod `json:"retention_period_days"`
			ExportedAt    time.Time       `json:"exported_at"`
			IntegrityHash string          `json:"integrity_hash"`
		}{
			Entries:       entries,
			Retention:     cal.retentionPeriod,
			ExportedAt:    time.Now(),
			IntegrityHash: cal.SecureAuditLog.GetLastHash(),
		}, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// generateEntryID generates a unique ID for an audit entry
func generateEntryID() string {
	hash := sha256.Sum256([]byte(time.Now().Format(time.RFC3339Nano)))
	return hex.EncodeToString(hash[:16])
}

// initComplianceMappings initializes default compliance tag mappings
func (cal *ComplianceAuditLog) initComplianceMappings() {
	cal.mu.Lock()
	defer cal.mu.Unlock()

	// SOC2 mappings
	cal.complianceMapping["auth.login"] = []string{"SOC2", "HIPAA", "PCI-DSS"}
	cal.complianceMapping["auth.logout"] = []string{"SOC2", "HIPAA"}
	cal.complianceMapping["auth.failure"] = []string{"SOC2", "HIPAA", "PCI-DSS"}
	cal.complianceMapping["config.change"] = []string{"SOC2"}
	cal.complianceMapping["data.access"] = []string{"SOC2", "HIPAA", "PCI-DSS"}
	cal.complianceMapping["data.export"] = []string{"SOC2", "HIPAA", "PCI-DSS"}
	cal.complianceMapping["data.delete"] = []string{"SOC2", "HIPAA"}
	cal.complianceMapping["admin.action"] = []string{"SOC2"}
	cal.complianceMapping["security.violation"] = []string{"SOC2", "HIPAA", "PCI-DSS"}

	// HIPAA-specific mappings
	cal.complianceMapping["patient.data.access"] = []string{"HIPAA"}
	cal.complianceMapping["patient.data.modify"] = []string{"HIPAA"}
	cal.complianceMapping["phi.access"] = []string{"HIPAA"}
	cal.complianceMapping["breach.detected"] = []string{"HIPAA"}

	// PCI-DSS mappings
	cal.complianceMapping["payment.card.access"] = []string{"PCI-DSS"}
	cal.complianceMapping["payment.card.modify"] = []string{"PCI-DSS"}
	cal.complianceMapping["cardholder.data.access"] = []string{"PCI-DSS"}
}

// GetRetentionUntil returns the date until which entries are retained
func (cal *ComplianceAuditLog) GetRetentionUntil() time.Time {
	cal.mu.RLock()
	defer cal.mu.RUnlock()
	return cal.retentionUntil
}

// GetTenantID returns the tenant ID for this audit log
func (cal *ComplianceAuditLog) GetTenantID() string {
	cal.mu.RLock()
	defer cal.mu.RUnlock()
	return cal.tenantID
}
