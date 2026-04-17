// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package wal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EntryType defines types of WAL entries
type EntryType string

const (
	EntryTypeSave     EntryType = "save"
	EntryTypeDelete   EntryType = "delete"
	EntryTypeRollback EntryType = "rollback"
	EntryTypeSnapshot EntryType = "snapshot"
	EntryTypeSeal     EntryType = "seal"
)

// Entry represents a single WAL entry
type Entry struct {
	ID        string                 `json:"id"`
	Type      EntryType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Version   string                 `json:"version,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
	Checksum  string                 `json:"checksum"`
	Status    string                 `json:"status"` // pending, committed, rolled_back
}

// WAL implements write-ahead logging for atomic operations
type WAL struct {
	mu         sync.RWMutex
	basePath   string
	entries    []*Entry
	entryMap   map[string]*Entry
	maxEntries int
	currentLSN int64 // Log Sequence Number
}

// WALOptions for configuring the WAL
type WALOptions struct {
	BasePath    string
	MaxEntries  int
	SyncOnWrite bool
}

// DefaultWALOptions returns default WAL options
func DefaultWALOptions() *WALOptions {
	return &WALOptions{
		BasePath:    "./wal-data",
		MaxEntries:  1000,
		SyncOnWrite: true,
	}
}

// NewWAL creates a new Write-Ahead Log
func NewWAL(opts *WALOptions) (*WAL, error) {
	if opts == nil {
		opts = DefaultWALOptions()
	}

	wal := &WAL{
		basePath:   opts.BasePath,
		entries:    make([]*Entry, 0),
		entryMap:   make(map[string]*Entry),
		maxEntries: opts.MaxEntries,
		currentLSN: 0,
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(opts.BasePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %w", err)
	}

	// Load existing entries
	if err := wal.load(); err != nil {
		return nil, fmt.Errorf("failed to load WAL: %w", err)
	}

	return wal, nil
}

// Append appends a new entry to the WAL
func (w *WAL) Append(entryType EntryType, version string, data map[string]interface{}, metadata map[string]string) (*Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Generate entry ID
	w.currentLSN++
	id := w.generateEntryID()

	entry := &Entry{
		ID:        id,
		Type:      entryType,
		Timestamp: time.Now().UTC(),
		Version:   version,
		Data:      data,
		Metadata:  metadata,
		Status:    "pending",
	}

	// Calculate checksum
	checksum, err := w.calculateChecksum(entry)
	if err != nil {
		return nil, err
	}
	entry.Checksum = checksum

	// Append to in-memory log
	w.entries = append(w.entries, entry)
	w.entryMap[id] = entry

	// Persist to disk
	if err := w.persistEntry(entry); err != nil {
		return nil, err
	}

	// Trim old entries if needed
	w.trimEntries()

	return entry, nil
}

// Commit marks an entry as committed
func (w *WAL) Commit(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	entry, exists := w.entryMap[id]
	if !exists {
		return fmt.Errorf("entry %s not found", id)
	}

	entry.Status = "committed"
	return w.updateEntryStatus(id, "committed")
}

// Rollback marks an entry as rolled back
func (w *WAL) Rollback(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	entry, exists := w.entryMap[id]
	if !exists {
		return fmt.Errorf("entry %s not found", id)
	}

	entry.Status = "rolled_back"
	return w.updateEntryStatus(id, "rolled_back")
}

// Get retrieves an entry by ID
func (w *WAL) Get(id string) (*Entry, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	entry, exists := w.entryMap[id]
	if !exists {
		return nil, fmt.Errorf("entry %s not found", id)
	}

	return entry, nil
}

// List lists all entries (optionally filtered by type or status)
func (w *WAL) List(entryType EntryType, status string) []*Entry {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var entries []*Entry
	for _, entry := range w.entries {
		if entryType != "" && entry.Type != entryType {
			continue
		}
		if status != "" && entry.Status != status {
			continue
		}
		entries = append(entries, entry)
	}

	return entries
}

// ListPending returns all pending entries
func (w *WAL) ListPending() []*Entry {
	return w.List("", "pending")
}

// ListCommitted returns all committed entries
func (w *WAL) ListCommitted() []*Entry {
	return w.List("", "committed")
}

// Recover replays committed entries for recovery
func (w *WAL) Recover(handler func(entry *Entry) error) error {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, entry := range w.entries {
		if entry.Status != "committed" {
			continue
		}

		// Verify checksum
		checksum, err := w.calculateChecksum(entry)
		if err != nil {
			return fmt.Errorf("failed to verify checksum for entry %s: %w", entry.ID, err)
		}

		if checksum != entry.Checksum {
			return fmt.Errorf("checksum mismatch for entry %s", entry.ID)
		}

		// Call handler
		if err := handler(entry); err != nil {
			return fmt.Errorf("failed to recover entry %s: %w", entry.ID, err)
		}
	}

	return nil
}

// Compact compacts the WAL by removing old committed entries
func (w *WAL) Compact() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var newEntries []*Entry
	newEntryMap := make(map[string]*Entry)

	for _, entry := range w.entries {
		// Keep pending entries
		if entry.Status == "pending" {
			newEntries = append(newEntries, entry)
			newEntryMap[entry.ID] = entry
		}
	}

	w.entries = newEntries
	w.entryMap = newEntryMap

	// Rewrite the WAL file
	return w.saveAll()
}

// Clear clears all WAL entries
func (w *WAL) Clear() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.entries = make([]*Entry, 0)
	w.entryMap = make(map[string]*Entry)

	// Remove all WAL files
	entries, err := os.ReadDir(w.basePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".wal" {
			if err := os.Remove(filepath.Join(w.basePath, entry.Name())); err != nil {
				// Log but continue - best effort cleanup
			}
		}
	}

	return nil
}

// Close closes the WAL
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.saveAll()
}

// GetLatestLSN returns the latest log sequence number
func (w *WAL) GetLatestLSN() int64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.currentLSN
}

// GetStats returns WAL statistics
func (w *WAL) GetStats() map[string]int64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var pending, committed, rolledBack int64
	for _, entry := range w.entries {
		switch entry.Status {
		case "pending":
			pending++
		case "committed":
			committed++
		case "rolled_back":
			rolledBack++
		}
	}

	return map[string]int64{
		"total_entries": int64(len(w.entries)),
		"pending":       pending,
		"committed":     committed,
		"rolled_back":   rolledBack,
		"current_lsn":   w.currentLSN,
		"max_entries":   int64(w.maxEntries),
	}
}

// Private methods

func (w *WAL) generateEntryID() string {
	data := fmt.Sprintf("wal-%d-%d", w.currentLSN, time.Now().UTC().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func (w *WAL) calculateChecksum(entry *Entry) (string, error) {
	data, err := json.Marshal(map[string]interface{}{
		"id":        entry.ID,
		"type":      entry.Type,
		"timestamp": entry.Timestamp.Format(time.RFC3339Nano),
		"version":   entry.Version,
		"data":      entry.Data,
		"metadata":  entry.Metadata,
	})
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func (w *WAL) persistEntry(entry *Entry) error {
	entryPath := filepath.Join(w.basePath, entry.ID+".wal")
	entryData, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(entryPath, entryData, 0644)
}

func (w *WAL) updateEntryStatus(id string, status string) error {
	entry, exists := w.entryMap[id]
	if !exists {
		return fmt.Errorf("entry %s not found", id)
	}

	return w.persistEntry(entry)
}

func (w *WAL) load() error {
	entries, err := os.ReadDir(w.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".wal" {
			continue
		}

		entryPath := filepath.Join(w.basePath, entry.Name())
		entryData, err := os.ReadFile(entryPath)
		if err != nil {
			continue
		}

		var walEntry Entry
		if err := json.Unmarshal(entryData, &walEntry); err != nil {
			continue
		}

		w.entries = append(w.entries, &walEntry)
		w.entryMap[walEntry.ID] = &walEntry

		// Update LSN
		w.currentLSN++
	}

	return nil
}

func (w *WAL) saveAll() error {
	for _, entry := range w.entries {
		if err := w.persistEntry(entry); err != nil {
			return err
		}
	}
	return nil
}

func (w *WAL) trimEntries() {
	if len(w.entries) <= w.maxEntries {
		return
	}

	var newEntries []*Entry
	newEntryMap := make(map[string]*Entry)

	pendingCount := 0
	for i := len(w.entries) - 1; i >= 0; i-- {
		entry := w.entries[i]
		if entry.Status == "pending" {
			newEntries = append([]*Entry{entry}, newEntries...)
			newEntryMap[entry.ID] = entry
			pendingCount++
		} else if len(newEntries) < w.maxEntries {
			newEntries = append([]*Entry{entry}, newEntries...)
			newEntryMap[entry.ID] = entry
		}
	}

	w.entries = newEntries
	w.entryMap = newEntryMap

	w.cleanupOrphanedFiles()
}

func (w *WAL) cleanupOrphanedFiles() {
	entries, err := os.ReadDir(w.basePath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".wal" {
			continue
		}

		id := entry.Name()[:len(entry.Name())-4]
		if _, exists := w.entryMap[id]; !exists {
			if err := os.Remove(filepath.Join(w.basePath, entry.Name())); err != nil {
				// Log but continue - best effort cleanup
			}
		}
	}
}
