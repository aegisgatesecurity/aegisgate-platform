// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package logging

import (
	"fmt"
	"sync"
	"time"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	Version   string    `json:"version"`
	User      string    `json:"user,omitempty"`
	Operation string    `json:"operation"`
	Details   string    `json:"details,omitempty"`
	Hash      string    `json:"hash"`
	Signature string    `json:"signature,omitempty"`
}

// AuditLogger handles audit logging for configuration changes
type AuditLogger struct {
	entries    []*AuditEntry
	mu         sync.RWMutex
	maxEntries int
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(maxEntries int) *AuditLogger {
	return &AuditLogger{
		entries:    make([]*AuditEntry, 0),
		maxEntries: maxEntries,
	}
}

// Log logs a new audit entry
func (al *AuditLogger) Log(eventType string, version string, operation string, details string, hash string, signature string) *AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	entry := &AuditEntry{
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Version:   version,
		Operation: operation,
		Details:   details,
		Hash:      hash,
		Signature: signature,
	}

	al.entries = append(al.entries, entry)

	// Trim old entries if we exceed max
	if len(al.entries) > al.maxEntries {
		al.entries = al.entries[len(al.entries)-al.maxEntries:]
	}

	return entry
}

// GetEntries returns all audit entries
func (al *AuditLogger) GetEntries() []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.entries
}

// GetLatestEntry returns the most recent audit entry
func (al *AuditLogger) GetLatestEntry() *AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()
	if len(al.entries) == 0 {
		return nil
	}
	return al.entries[len(al.entries)-1]
}

// GetEntriesByType returns entries filtered by event type
func (al *AuditLogger) GetEntriesByType(eventType string) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var filtered []*AuditEntry
	for _, entry := range al.entries {
		if entry.EventType == eventType {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// GetEntriesByVersion returns entries for a specific version
func (al *AuditLogger) GetEntriesByVersion(version string) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var filtered []*AuditEntry
	for _, entry := range al.entries {
		if entry.Version == version {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// String implements fmt.Stringer for formatted output
func (e *AuditEntry) String() string {
	hashPreview := e.Hash
	if len(hashPreview) > 16 {
		hashPreview = hashPreview[:16]
	}
	return fmt.Sprintf("[%s] %s: Version=%s, Operation=%s, Hash=%s",
		e.Timestamp.Format(time.RFC3339),
		e.EventType,
		e.Version,
		e.Operation, hashPreview)
}

// AuditEntry types
const (
	EventConfigSave     = "config_save"
	EventConfigLoad     = "config_load"
	EventConfigRollback = "config_rollback"
	EventConfigDelete   = "config_delete"
	EventIntegrityFail  = "integrity_fail"
	EventSignatureFail  = "signature_fail"
)
