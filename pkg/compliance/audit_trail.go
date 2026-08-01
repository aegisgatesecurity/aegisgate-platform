// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Audit Trail - Rule Change Tracking for Compliance Patterns
// =========================================================================
//
// This module provides a complete audit trail system for tracking changes
// to compliance patterns (ATLAS, OWASP, and others). It records who changed
// what, when, why, and supports version diffing and rollback descriptions.

package compliance

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// ChangeType represents the type of change made to a compliance pattern.
type ChangeType string

const (
	// ChangeTypeAdded indicates a new pattern was added.
	ChangeTypeAdded ChangeType = "added"
	// ChangeTypeModified indicates an existing pattern was modified.
	ChangeTypeModified ChangeType = "modified"
	// ChangeTypeRemoved indicates a pattern was removed.
	ChangeTypeRemoved ChangeType = "removed"
	// ChangeTypeEnabled indicates a pattern was enabled.
	ChangeTypeEnabled ChangeType = "enabled"
	// ChangeTypeDisabled indicates a pattern was disabled.
	ChangeTypeDisabled ChangeType = "disabled"
)

// AuditEntry records a single change to a compliance pattern.
type AuditEntry struct {
	// ID is a unique identifier for this audit entry, auto-generated.
	ID string `json:"id"`
	// Timestamp is when the change occurred.
	Timestamp time.Time `json:"timestamp"`
	// PatternID identifies which pattern was changed.
	PatternID string `json:"pattern_id"`
	// Framework identifies which compliance framework the pattern belongs to.
	Framework Framework `json:"framework"`
	// ChangeType describes the kind of change (added, modified, removed, etc.).
	ChangeType ChangeType `json:"change_type"`
	// Field indicates which field of the pattern changed (e.g. "regex", "severity").
	Field string `json:"field"`
	// OldValue is the value before the change.
	OldValue string `json:"old_value"`
	// NewValue is the value after the change.
	NewValue string `json:"new_value"`
	// Reason provides justification for the change.
	Reason string `json:"reason"`
	// Author identifies who made the change.
	Author string `json:"author"`
	// Version tracks the version number of the pattern after this change.
	Version int `json:"version"`
}

// PatternSnapshot captures the complete state of a pattern at a point in time.
type PatternSnapshot struct {
	PatternID   string    `json:"pattern_id"`
	Technique   string    `json:"technique"`
	Framework   Framework `json:"framework"`
	Severity    Severity  `json:"severity"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Block       bool      `json:"block"`
	RegexStr    string    `json:"regex"`
	CapturedAt  time.Time `json:"captured_at"`
}

// DiffResult represents a single field-level difference between two pattern versions.
type DiffResult struct {
	Field      string     `json:"field"`
	OldValue   string     `json:"old_value"`
	NewValue   string     `json:"new_value"`
	ChangeType ChangeType  `json:"change_type"`
}

// AuditQuery defines filter parameters for querying audit entries.
type AuditQuery struct {
	// PatternID filters by pattern identifier.
	PatternID string `json:"pattern_id,omitempty"`
	// Framework filters by compliance framework.
	Framework Framework `json:"framework,omitempty"`
	// ChangeType filters by type of change.
	ChangeType ChangeType `json:"change_type,omitempty"`
	// Since filters entries after this time.
	Since time.Time `json:"since,omitempty"`
	// Until filters entries before this time.
	Until time.Time `json:"until,omitempty"`
	// Author filters by who made the change.
	Author string `json:"author,omitempty"`
	// Limit restricts the maximum number of entries returned (0 = no limit).
	Limit int `json:"limit,omitempty"`
}

// AuditStats provides summary statistics for the audit trail.
type AuditStats struct {
	TotalEntries  int              `json:"total_entries"`
	ByFramework  map[string]int    `json:"by_framework"`
	ByChangeType map[ChangeType]int `json:"by_change_type"`
	ByAuthor     map[string]int    `json:"by_author"`
	Earliest     time.Time         `json:"earliest"`
	Latest       time.Time         `json:"latest"`
}

// AuditTrail tracks changes to compliance patterns with full audit capability.
type AuditTrail struct {
	entries    []AuditEntry
	mu         sync.RWMutex
	versionMap map[string]int // patternID -> current version number
}

// NewAuditTrail creates a new empty audit trail.
func NewAuditTrail() *AuditTrail {
	return &AuditTrail{
		entries:    make([]AuditEntry, 0),
		versionMap: make(map[string]int),
	}
}

// generateAuditID creates a unique identifier for an audit entry.
func generateAuditID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Record adds an audit entry to the trail and assigns version numbers.
func (at *AuditTrail) Record(entry AuditEntry) AuditEntry {
	at.mu.Lock()
	defer at.mu.Unlock()

	if entry.ID == "" {
		entry.ID = generateAuditID()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// Increment version for this pattern
	v := at.versionMap[entry.PatternID] + 1
	at.versionMap[entry.PatternID] = v
	entry.Version = v

	at.entries = append(at.entries, entry)
	return entry
}

// RecordPatternChange compares old and new Pattern states and creates
// AuditEntry records for every field that changed. Returns the list of
// entries created (may be empty if no fields changed).
func (at *AuditTrail) RecordPatternChange(old, new *Pattern, author, reason string) []AuditEntry {
	if old == nil || new == nil {
		return nil
	}

	var entries []AuditEntry
	ts := time.Now().UTC()

	// Compare each field
	type fieldCompare struct {
		name    string
		oldVal  string
		newVal  string
	}

	comparisons := []fieldCompare{
		{"regex", old.Regex.String(), new.Regex.String()},
		{"severity", string(old.Severity), string(new.Severity)},
		{"description", old.Description, new.Description},
		{"category", old.Category, new.Category},
		{"block", fmt.Sprintf("%v", old.Block), fmt.Sprintf("%v", new.Block)},
		{"technique", old.Technique, new.Technique},
		{"framework", string(old.Framework), string(new.Framework)},
	}

	for _, c := range comparisons {
		if c.oldVal != c.newVal {
			entry := AuditEntry{
				ID:         generateAuditID(),
				Timestamp:  ts,
				PatternID:  new.ID,
				Framework:  new.Framework,
				ChangeType: ChangeTypeModified,
				Field:      c.name,
				OldValue:   c.oldVal,
				NewValue:   c.newVal,
				Reason:     reason,
				Author:     author,
			}
			entry = at.Record(entry)
			entries = append(entries, entry)
		}
	}

	return entries
}

// RecordPatternAddition records the addition of a new pattern.
func (at *AuditTrail) RecordPatternAddition(p *Pattern, author, reason string) AuditEntry {
	if p == nil {
		return AuditEntry{}
	}

	entry := AuditEntry{
		Timestamp:  time.Now().UTC(),
		PatternID:  p.ID,
		Framework:  p.Framework,
		ChangeType: ChangeTypeAdded,
		Field:      "pattern",
		OldValue:   "",
		NewValue:   fmt.Sprintf("Added pattern %s", p.ID),
		Reason:     reason,
		Author:     author,
	}
	return at.Record(entry)
}

// RecordPatternRemoval records the removal of a pattern.
func (at *AuditTrail) RecordPatternRemoval(p *Pattern, author, reason string) AuditEntry {
	if p == nil {
		return AuditEntry{}
	}

	entry := AuditEntry{
		Timestamp:  time.Now().UTC(),
		PatternID:  p.ID,
		Framework:  p.Framework,
		ChangeType: ChangeTypeRemoved,
		Field:      "pattern",
		OldValue:   fmt.Sprintf("Removed pattern %s", p.ID),
		NewValue:   "",
		Reason:     reason,
		Author:     author,
	}
	return at.Record(entry)
}

// Query filters audit entries based on the provided query parameters.
// Entries are returned in chronological order (oldest first).
func (at *AuditTrail) Query(q AuditQuery) []AuditEntry {
	at.mu.RLock()
	defer at.mu.RUnlock()

	var results []AuditEntry

	for _, e := range at.entries {
		if q.PatternID != "" && e.PatternID != q.PatternID {
			continue
		}
		if q.Framework != "" && e.Framework != q.Framework {
			continue
		}
		if q.ChangeType != "" && e.ChangeType != q.ChangeType {
			continue
		}
		if !q.Since.IsZero() && e.Timestamp.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && e.Timestamp.After(q.Until) {
			continue
		}
		if q.Author != "" && e.Author != q.Author {
			continue
		}
		results = append(results, e)
	}

	// Sort by timestamp
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.Before(results[j].Timestamp)
	})

	// Apply limit
	if q.Limit > 0 && len(results) > q.Limit {
		results = results[len(results)-q.Limit:]
	}

	return results
}

// GetHistory returns the full change history for a specific pattern, ordered chronologically.
func (at *AuditTrail) GetHistory(patternID string) []AuditEntry {
	at.mu.RLock()
	defer at.mu.RUnlock()

	var results []AuditEntry
	for _, e := range at.entries {
		if e.PatternID == patternID {
			results = append(results, e)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.Before(results[j].Timestamp)
	})

	return results
}

// Diff computes the differences between two versions of a pattern's history.
// It looks up all audit entries for the given pattern, identifies the entries
// corresponding to fromVersion and toVersion, and returns the field-level diffs.
func (at *AuditTrail) Diff(patternID string, fromVersion, toVersion int) []DiffResult {
	at.mu.RLock()
	defer at.mu.RUnlock()

	// Collect all entries for this pattern
	var patternEntries []AuditEntry
	for _, e := range at.entries {
		if e.PatternID == patternID {
			patternEntries = append(patternEntries, e)
		}
	}

	sort.Slice(patternEntries, func(i, j int) bool {
		return patternEntries[i].Version < patternEntries[j].Version
	})

	// Build state at each version
	type versionState struct {
		version int
		fields  map[string]string
	}

	states := make(map[int]map[string]string)

	// Start from base state (before any changes)
	base := map[string]string{}
	for _, e := range patternEntries {
		// Apply the change
		if e.ChangeType == ChangeTypeAdded {
			base[e.Field] = e.NewValue
		} else if e.ChangeType == ChangeTypeModified {
			base[e.Field] = e.NewValue
		} else if e.ChangeType == ChangeTypeRemoved {
			base[e.Field] = ""
		} else if e.ChangeType == ChangeTypeEnabled || e.ChangeType == ChangeTypeDisabled {
			base[e.Field] = e.NewValue
		}
		// Snapshot state at this version
		snapshot := make(map[string]string)
		for k, v := range base {
			snapshot[k] = v
		}
		states[e.Version] = snapshot
	}

	fromState, fromOk := states[fromVersion]
	toState, toOk := states[toVersion]

	if !fromOk || !toOk {
		return nil
	}

	// Compute diff between fromState and toState
	return diffStates(fromState, toState)
}

// diffStates computes the field-level differences between two pattern state maps.
func diffStates(from, to map[string]string) []DiffResult {
	var diffs []DiffResult

	allFields := make(map[string]bool)
	for k := range from {
		allFields[k] = true
	}
	for k := range to {
		allFields[k] = true
	}

	for field := range allFields {
		fromVal, fromExists := from[field]
		toVal, toExists := to[field]

		if !fromExists && toExists {
			diffs = append(diffs, DiffResult{
				Field:      field,
				OldValue:   "",
				NewValue:   toVal,
				ChangeType: ChangeTypeAdded,
			})
		} else if fromExists && !toExists {
			diffs = append(diffs, DiffResult{
				Field:      field,
				OldValue:   fromVal,
				NewValue:   "",
				ChangeType: ChangeTypeRemoved,
			})
		} else if fromVal != toVal {
			diffs = append(diffs, DiffResult{
				Field:      field,
				OldValue:   fromVal,
				NewValue:   toVal,
				ChangeType: ChangeTypeModified,
			})
		}
	}

	sort.Slice(diffs, func(i, j int) bool {
		return diffs[i].Field < diffs[j].Field
	})

	return diffs
}

// SnapshotPattern captures the current state of a pattern as a PatternSnapshot.
func (at *AuditTrail) SnapshotPattern(p *Pattern) PatternSnapshot {
	if p == nil {
		return PatternSnapshot{}
	}

	regexStr := ""
	if p.Regex != nil {
		regexStr = p.Regex.String()
	}

	return PatternSnapshot{
		PatternID:   p.ID,
		Technique:   p.Technique,
		Framework:   p.Framework,
		Severity:    p.Severity,
		Category:    p.Category,
		Description: p.Description,
		Block:       p.Block,
		RegexStr:    regexStr,
		CapturedAt:  time.Now().UTC(),
	}
}

// ExportJSON exports all audit entries as JSON.
func (at *AuditTrail) ExportJSON() ([]byte, error) {
	at.mu.RLock()
	defer at.mu.RUnlock()

	data, err := json.MarshalIndent(at.entries, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit entries: %w", err)
	}
	return data, nil
}

// ImportJSON imports audit entries from JSON data, appending them to the trail.
func (at *AuditTrail) ImportJSON(data []byte) error {
	var entries []AuditEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to unmarshal audit entries: %w", err)
	}

	at.mu.Lock()
	defer at.mu.Unlock()

	// Update version map based on imported entries
	for _, e := range entries {
		if e.Version > at.versionMap[e.PatternID] {
			at.versionMap[e.PatternID] = e.Version
		}
	}

	at.entries = append(at.entries, entries...)
	return nil
}

// Stats returns summary statistics about the audit trail.
func (at *AuditTrail) Stats() AuditStats {
	at.mu.RLock()
	defer at.mu.RUnlock()

	stats := AuditStats{
		TotalEntries: len(at.entries),
		ByFramework: make(map[string]int),
		ByChangeType: make(map[ChangeType]int),
		ByAuthor:    make(map[string]int),
	}

	for _, e := range at.entries {
		stats.ByFramework[string(e.Framework)]++
		stats.ByChangeType[e.ChangeType]++
		stats.ByAuthor[e.Author]++

		if stats.Earliest.IsZero() || e.Timestamp.Before(stats.Earliest) {
			stats.Earliest = e.Timestamp
		}
		if stats.Latest.IsZero() || e.Timestamp.After(stats.Latest) {
			stats.Latest = e.Timestamp
		}
	}

	return stats
}

// ComparePatternSnapshots compares two PatternSnapshot instances and returns
// the field-level differences between them.
func ComparePatternSnapshots(old, new PatternSnapshot) []DiffResult {
	type fieldCompare struct {
		name   string
		oldVal string
		newVal string
	}

	comparisons := []fieldCompare{
		{"technique", old.Technique, new.Technique},
		{"framework", string(old.Framework), string(new.Framework)},
		{"severity", string(old.Severity), string(new.Severity)},
		{"category", old.Category, new.Category},
		{"description", old.Description, new.Description},
		{"block", fmt.Sprintf("%v", old.Block), fmt.Sprintf("%v", new.Block)},
		{"regex", old.RegexStr, new.RegexStr},
	}

	var diffs []DiffResult
	for _, c := range comparisons {
		if c.oldVal != c.newVal {
			ct := ChangeTypeModified
			if c.oldVal == "" {
				ct = ChangeTypeAdded
			} else if c.newVal == "" {
				ct = ChangeTypeRemoved
			}
			diffs = append(diffs, DiffResult{
				Field:      c.name,
				OldValue:   c.oldVal,
				NewValue:   c.newVal,
				ChangeType: ct,
			})
		}
	}

	return diffs
}

// RollbackDescription generates a human-readable description of what a pattern
// looked like before a given change, useful for understanding rollback impact.
func (at *AuditTrail) RollbackDescription(patternID string, version int) string {
	history := at.GetHistory(patternID)

	// Build state at the version before the target
	state := make(map[string]string)
	for _, e := range history {
		if e.Version >= version {
			break
		}
		if e.NewValue != "" {
			state[e.Field] = e.NewValue
		}
	}

	desc := fmt.Sprintf("Pattern %s at version %d rollback target:\n", patternID, version)
	for field, val := range state {
		desc += fmt.Sprintf("  %s: %s\n", field, val)
	}
	return desc
}

// AuditEntriesAsJSON is a convenience method that returns audit entries matching
// a query as JSON bytes, suitable for HTTP endpoint integration.
func (at *AuditTrail) AuditEntriesAsJSON(q AuditQuery) ([]byte, error) {
	entries := at.Query(q)
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit entries: %w", err)
	}
	return data, nil
}

// Ensure AuditTrail satisfies expected interfaces at compile time.
// The Pattern struct uses *regexp.Regexp for the Regex field; when comparing
// patterns we use Regex.String() to get the string representation.
var _ = regexp.MustCompile // reference to ensure regexp import is used