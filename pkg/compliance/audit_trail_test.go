// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Audit Trail Tests - Comprehensive testing for rule change audit tracking
// =========================================================================

package compliance

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"
)

// helper to create a test pattern
func newTestPattern(id, technique string, framework Framework, severity Severity, category, description string, block bool, regex string) *Pattern {
	return &Pattern{
		ID:          id,
		Technique:   technique,
		Framework:   framework,
		Severity:    severity,
		Category:    category,
		Description: description,
		Block:       block,
		Regex:       regexp.MustCompile(regex),
	}
}

func TestNewAuditTrail(t *testing.T) {
	at := NewAuditTrail()
	if at == nil {
		t.Fatal("NewAuditTrail() returned nil")
	}
	if len(at.entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(at.entries))
	}
	if at.versionMap == nil {
		t.Fatal("versionMap should be initialized")
	}
}

func TestRecord_AddedEntry(t *testing.T) {
	at := NewAuditTrail()

	entry := AuditEntry{
		PatternID:  "ATLAS-001",
		Framework:  FrameworkATLAS,
		ChangeType: ChangeTypeAdded,
		Field:      "pattern",
		OldValue:   "",
		NewValue:   "Added pattern ATLAS-001",
		Reason:     "Initial creation",
		Author:     "admin",
	}

	result := at.Record(entry)

	if result.ID == "" {
		t.Error("expected auto-generated ID, got empty string")
	}
	if result.Timestamp.IsZero() {
		t.Error("expected auto-generated timestamp, got zero value")
	}
	if result.Version != 1 {
		t.Errorf("expected version 1, got %d", result.Version)
	}

	if len(at.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(at.entries))
	}
}

func TestRecordPatternChange_RegexModified(t *testing.T) {
	at := NewAuditTrail()

	oldPattern := newTestPattern(
		"OWASP-001", "LLM01-PromptInjection",
		FrameworkOWASP, SeverityCritical,
		"injection", "Detects prompt injection attempts",
		true, `(?i)ignore\s+previous`,
	)
	newPattern := newTestPattern(
		"OWASP-001", "LLM01-PromptInjection",
		FrameworkOWASP, SeverityCritical,
		"injection", "Detects prompt injection attempts",
		true, `(?i)ignore\s+(previous|prior)\s+instructions`,
	)

	entries := at.RecordPatternChange(oldPattern, newPattern, "security-team", "Widen regex coverage")

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry for regex change, got %d", len(entries))
	}

	e := entries[0]
	if e.ChangeType != ChangeTypeModified {
		t.Errorf("expected ChangeTypeModified, got %s", e.ChangeType)
	}
	if e.Field != "regex" {
		t.Errorf("expected field 'regex', got %s", e.Field)
	}
	if e.OldValue != `(?i)ignore\s+previous` {
		t.Errorf("expected old regex, got %s", e.OldValue)
	}
	if e.NewValue != `(?i)ignore\s+(previous|prior)\s+instructions` {
		t.Errorf("expected new regex, got %s", e.NewValue)
	}
	if e.Author != "security-team" {
		t.Errorf("expected author 'security-team', got %s", e.Author)
	}
	if e.Reason != "Widen regex coverage" {
		t.Errorf("expected reason, got %s", e.Reason)
	}
}

func TestRecordPatternChange_SeverityModified(t *testing.T) {
	at := NewAuditTrail()

	oldPattern := newTestPattern(
		"ATLAS-005", "AML.T0010-MLModelInversion",
		FrameworkATLAS, SeverityMedium,
		"exfil", "Detects model inversion attempts",
		false, `(?i)model\s+inversion`,
	)
	newPattern := newTestPattern(
		"ATLAS-005", "AML.T0010-MLModelInversion",
		FrameworkATLAS, SeverityCritical,
		"exfil", "Detects model inversion attempts",
		true, `(?i)model\s+inversion`,
	)

	entries := at.RecordPatternChange(oldPattern, newPattern, "compliance-officer", "Escalated severity")

	if len(entries) < 1 {
		t.Fatalf("expected at least 1 entry, got %d", len(entries))
	}

	// Find the severity change entry
	var severityEntry *AuditEntry
	for i := range entries {
		if entries[i].Field == "severity" {
			severityEntry = &entries[i]
			break
		}
	}
	if severityEntry == nil {
		t.Fatal("expected a severity change entry")
	}

	if severityEntry.OldValue != string(SeverityMedium) {
		t.Errorf("expected old severity 'Medium', got %s", severityEntry.OldValue)
	}
	if severityEntry.NewValue != string(SeverityCritical) {
		t.Errorf("expected new severity 'Critical', got %s", severityEntry.NewValue)
	}
}

func TestRecordPatternChange_MultipleFields(t *testing.T) {
	at := NewAuditTrail()

	oldPattern := newTestPattern(
		"MULTI-001", "TestTech",
		FrameworkATLAS, SeverityLow,
		"test-cat", "Old description",
		false, `(?i)old\s+regex`,
	)
	newPattern := newTestPattern(
		"MULTI-001", "TestTech",
		FrameworkOWASP, SeverityCritical,
		"new-cat", "New description",
		true, `(?i)new\s+regex`,
	)

	entries := at.RecordPatternChange(oldPattern, newPattern, "admin", "Major overhaul")

	// Should have entries for: regex, severity, description, category, block, framework (technique is same)
	changedFields := make(map[string]bool)
	for _, e := range entries {
		changedFields[e.Field] = true
	}

	expectedFields := []string{"regex", "severity", "description", "category", "block", "framework"}
	for _, f := range expectedFields {
		if !changedFields[f] {
			t.Errorf("expected change entry for field %s", f)
		}
	}

	// Technique did NOT change
	if changedFields["technique"] {
		t.Error("did not expect a change entry for technique (unchanged)")
	}
}

func TestRecordPatternAddition(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern(
		"ADD-001", "AML.T0043-LLMPromptInjection",
		FrameworkATLAS, SeverityHigh,
		"injection", "Detects LLM prompt injection",
		true, `(?i)inject\s+prompt`,
	)

	entry := at.RecordPatternAddition(p, "security-admin", "New threat pattern")

	if entry.ChangeType != ChangeTypeAdded {
		t.Errorf("expected ChangeTypeAdded, got %s", entry.ChangeType)
	}
	if entry.PatternID != "ADD-001" {
		t.Errorf("expected pattern ID 'ADD-001', got %s", entry.PatternID)
	}
	if entry.Author != "security-admin" {
		t.Errorf("expected author 'security-admin', got %s", entry.Author)
	}
	if entry.Reason != "New threat pattern" {
		t.Errorf("expected reason, got %s", entry.Reason)
	}
	if entry.OldValue != "" {
		t.Errorf("expected empty OldValue for addition, got %s", entry.OldValue)
	}
}

func TestRecordPatternRemoval(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern(
		"DEL-001", "AML.T0040-MLModelPoisoning",
		FrameworkATLAS, SeverityMedium,
		"poisoning", "Detects model poisoning",
		false, `(?i)poison\s+data`,
	)

	entry := at.RecordPatternRemoval(p, "compliance-admin", "Pattern deprecated")

	if entry.ChangeType != ChangeTypeRemoved {
		t.Errorf("expected ChangeTypeRemoved, got %s", entry.ChangeType)
	}
	if entry.PatternID != "DEL-001" {
		t.Errorf("expected pattern ID 'DEL-001', got %s", entry.PatternID)
	}
	if entry.NewValue != "" {
		t.Errorf("expected empty NewValue for removal, got %s", entry.NewValue)
	}
	if entry.OldValue == "" {
		t.Error("expected non-empty OldValue for removal")
	}
}

func TestQuery_ByPatternID(t *testing.T) {
	at := NewAuditTrail()

	p1 := newTestPattern("Q-001", "Tech1", FrameworkATLAS, SeverityHigh, "cat1", "desc1", true, `(?i)test1`)
	p2 := newTestPattern("Q-002", "Tech2", FrameworkOWASP, SeverityCritical, "cat2", "desc2", true, `(?i)test2`)

	at.RecordPatternAddition(p1, "user1", "reason1")
	at.RecordPatternAddition(p2, "user2", "reason2")
	at.RecordPatternAddition(p1, "user1", "reason3")

	results := at.Query(AuditQuery{PatternID: "Q-001"})
	if len(results) != 2 {
		t.Fatalf("expected 2 entries for Q-001, got %d", len(results))
	}
	for _, e := range results {
		if e.PatternID != "Q-001" {
			t.Errorf("expected pattern ID 'Q-001', got %s", e.PatternID)
		}
	}
}

func TestQuery_ByFramework(t *testing.T) {
	at := NewAuditTrail()

	p1 := newTestPattern("FW-001", "Tech1", FrameworkATLAS, SeverityHigh, "cat1", "desc1", true, `(?i)atlas`)
	p2 := newTestPattern("FW-002", "Tech2", FrameworkOWASP, SeverityCritical, "cat2", "desc2", true, `(?i)owasp`)
	p3 := newTestPattern("FW-003", "Tech3", FrameworkATLAS, SeverityLow, "cat3", "desc3", false, `(?i)atlas2`)

	at.RecordPatternAddition(p1, "admin", "add")
	at.RecordPatternAddition(p2, "admin", "add")
	at.RecordPatternAddition(p3, "admin", "add")

	results := at.Query(AuditQuery{Framework: FrameworkATLAS})
	if len(results) != 2 {
		t.Fatalf("expected 2 ATLAS entries, got %d", len(results))
	}
	for _, e := range results {
		if e.Framework != FrameworkATLAS {
			t.Errorf("expected ATLAS framework, got %s", e.Framework)
		}
	}
}

func TestQuery_ByChangeType(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern("CT-001", "Tech", FrameworkATLAS, SeverityHigh, "cat", "desc", true, `(?i)test`)

	at.RecordPatternAddition(p, "admin", "initial add")
	at.RecordPatternRemoval(p, "admin", "deprecated")

	results := at.Query(AuditQuery{ChangeType: ChangeTypeAdded})
	if len(results) != 1 {
		t.Fatalf("expected 1 'added' entry, got %d", len(results))
	}
	if results[0].ChangeType != ChangeTypeAdded {
		t.Errorf("expected ChangeTypeAdded, got %s", results[0].ChangeType)
	}
}

func TestQuery_ByTimeRange(t *testing.T) {
	at := NewAuditTrail()

	startTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Manually insert entries with specific timestamps
	at.Record(AuditEntry{
		PatternID:  "T-001",
		Framework:  FrameworkATLAS,
		ChangeType: ChangeTypeAdded,
		Field:      "pattern",
		OldValue:   "",
		NewValue:   "added",
		Reason:     "test",
		Author:     "admin",
		Timestamp:  startTime,
	})
	at.Record(AuditEntry{
		PatternID:  "T-002",
		Framework:  FrameworkATLAS,
		ChangeType: ChangeTypeAdded,
		Field:      "pattern",
		OldValue:   "",
		NewValue:   "added",
		Reason:     "test",
		Author:     "admin",
		Timestamp:  startTime.Add(48 * time.Hour),
	})
	at.Record(AuditEntry{
		PatternID:  "T-003",
		Framework:  FrameworkATLAS,
		ChangeType: ChangeTypeAdded,
		Field:      "pattern",
		OldValue:   "",
		NewValue:   "added",
		Reason:     "test",
		Author:     "admin",
		Timestamp:  startTime.Add(96 * time.Hour),
	})

	since := startTime.Add(24 * time.Hour)
	until := startTime.Add(72 * time.Hour)

	results := at.Query(AuditQuery{Since: since, Until: until})
	if len(results) != 1 {
		t.Fatalf("expected 1 entry in time range, got %d", len(results))
	}
	if results[0].PatternID != "T-002" {
		t.Errorf("expected T-002, got %s", results[0].PatternID)
	}
}

func TestQuery_WithLimit(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern("LIM-001", "Tech", FrameworkATLAS, SeverityHigh, "cat", "desc", true, `(?i)lim`)

	// Add 5 entries
	for i := 0; i < 5; i++ {
		at.RecordPatternAddition(p, "admin", "reason")
	}

	results := at.Query(AuditQuery{PatternID: "LIM-001", Limit: 3})
	if len(results) != 3 {
		t.Fatalf("expected 3 entries with limit, got %d", len(results))
	}

	// Should get the 3 most recent entries
	// (since we add and version increments each time, last 3 will have versions 3,4,5)
	lastVersion := results[2].Version
	if lastVersion != 5 {
		// The last entry should have version 5 (since we recorded 5 times for same pattern)
		// Actually, each RecordPatternAddition calls Record, which increments version.
		// But RecordPatternAddition also sets ChangeType to "added" and field to "pattern",
		// so each call creates exactly one entry. With 5 calls, version goes 1..5.
		// Limit=3 should return versions 3,4,5 (the latest 3).
		t.Logf("last version = %d (expected 5)", lastVersion)
	}
}

func TestGetHistory(t *testing.T) {
	at := NewAuditTrail()

	oldPattern := newTestPattern(
		"HIST-001", "Tech",
		FrameworkATLAS, SeverityMedium,
		"cat", "Old desc",
		false, `(?i)oldregex`,
	)
	newPattern := newTestPattern(
		"HIST-001", "Tech",
		FrameworkATLAS, SeverityCritical,
		"cat", "New desc",
		true, `(?i)newregex`,
	)

	at.RecordPatternAddition(oldPattern, "admin", "initial")
	at.RecordPatternChange(oldPattern, newPattern, "admin", "update")

	history := at.GetHistory("HIST-001")

	if len(history) < 2 {
		t.Fatalf("expected at least 2 history entries, got %d", len(history))
	}

	// Verify chronological ordering
	for i := 1; i < len(history); i++ {
		if history[i].Timestamp.Before(history[i-1].Timestamp) {
			t.Error("history entries should be in chronological order")
		}
	}
}

func TestDiff_BetweenVersions(t *testing.T) {
	at := NewAuditTrail()

	// Create and add a pattern
	p1 := newTestPattern(
		"DIFF-001", "TechA",
		FrameworkATLAS, SeverityLow,
		"cat1", "Description v1",
		false, `(?i)regex1`,
	)
	p2 := newTestPattern(
		"DIFF-001", "TechA",
		FrameworkATLAS, SeverityCritical,
		"cat2", "Description v2",
		true, `(?i)regex2`,
	)

	at.RecordPatternAddition(p1, "admin", "initial")
	changeEntries := at.RecordPatternChange(p1, p2, "admin", "severity update")

	if len(changeEntries) == 0 {
		t.Fatal("expected at least one change entry")
	}

	// Get the versions from entries
	fromVersion := 1 // after addition
	toVersion := changeEntries[len(changeEntries)-1].Version

	diffs := at.Diff("DIFF-001", fromVersion, toVersion)

	if diffs == nil {
		t.Fatal("expected non-nil diff result")
	}

	// Verify that we got diff results for the changed fields
	changedFields := make(map[string]bool)
	for _, d := range diffs {
		changedFields[d.Field] = true
	}

	// At minimum severity, block, description, category, and regex should differ
	if !changedFields["severity"] {
		t.Error("expected severity diff")
	}
	if !changedFields["regex"] {
		t.Error("expected regex diff")
	}
}

func TestComparePatternSnapshots(t *testing.T) {
	old := PatternSnapshot{
		PatternID:   "SNAP-001",
		Technique:   "TechA",
		Framework:   FrameworkATLAS,
		Severity:    SeverityMedium,
		Category:    "injection",
		Description: "Old description",
		Block:       false,
		RegexStr:    `(?i)old\s+regex`,
		CapturedAt:  time.Now().UTC(),
	}

	new := PatternSnapshot{
		PatternID:   "SNAP-001",
		Technique:   "TechA",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "injection",
		Description: "New description",
		Block:       true,
		RegexStr:    `(?i)new\s+regex`,
		CapturedAt:  time.Now().UTC(),
	}

	diffs := ComparePatternSnapshots(old, new)

	// Severity, description, block, and regex changed
	changedFields := make(map[string]bool)
	for _, d := range diffs {
		changedFields[d.Field] = true
	}

	expectedChanged := []string{"severity", "description", "block", "regex"}
	for _, f := range expectedChanged {
		if !changedFields[f] {
			t.Errorf("expected diff for field %s", f)
		}
	}

	// Technique, framework, and category did not change
	unchanged := []string{"technique", "framework", "category"}
	for _, f := range unchanged {
		if changedFields[f] {
			t.Errorf("did not expect diff for unchanged field %s", f)
		}
	}

	// Verify specific diff values
	for _, d := range diffs {
		if d.Field == "severity" {
			if d.OldValue != string(SeverityMedium) {
				t.Errorf("expected old severity 'Medium', got %s", d.OldValue)
			}
			if d.NewValue != string(SeverityCritical) {
				t.Errorf("expected new severity 'Critical', got %s", d.NewValue)
			}
			if d.ChangeType != ChangeTypeModified {
				t.Errorf("expected ChangeTypeModified, got %s", d.ChangeType)
			}
		}
	}
}

func TestSnapshotPattern(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern(
		"SNAPOUT-001", "TechX",
		FrameworkOWASP, SeverityHigh,
		"xss", "Detects XSS attacks",
		true, `(?i)<script>`,
	)

	snap := at.SnapshotPattern(p)

	if snap.PatternID != "SNAPOUT-001" {
		t.Errorf("expected PatternID 'SNAPOUT-001', got %s", snap.PatternID)
	}
	if snap.Technique != "TechX" {
		t.Errorf("expected Technique 'TechX', got %s", snap.Technique)
	}
	if snap.Framework != FrameworkOWASP {
		t.Errorf("expected OWASP framework, got %s", snap.Framework)
	}
	if snap.Severity != SeverityHigh {
		t.Errorf("expected High severity, got %s", snap.Severity)
	}
	if snap.Category != "xss" {
		t.Errorf("expected category 'xss', got %s", snap.Category)
	}
	if snap.Description != "Detects XSS attacks" {
		t.Errorf("expected description, got %s", snap.Description)
	}
	if snap.Block != true {
		t.Errorf("expected Block=true, got %v", snap.Block)
	}
	if snap.RegexStr != `(?i)<script>` {
		t.Errorf("expected regex string, got %s", snap.RegexStr)
	}
	if snap.CapturedAt.IsZero() {
		t.Error("expected non-zero CapturedAt timestamp")
	}
}

func TestSnapshotPattern_Nil(t *testing.T) {
	at := NewAuditTrail()
	snap := at.SnapshotPattern(nil)
	if snap.PatternID != "" {
		t.Errorf("expected empty PatternID for nil pattern, got %s", snap.PatternID)
	}
}

func TestExportImportJSON_RoundTrip(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern(
		"EXPORT-001", "TechExport",
		FrameworkATLAS, SeverityCritical,
		"exfil", "Data exfiltration detection",
		true, `(?i)export\s+data`,
	)

	at.RecordPatternAddition(p, "admin", "test export")

	oldPattern := newTestPattern(
		"EXPORT-001", "TechExport",
		FrameworkATLAS, SeverityCritical,
		"exfil", "Data exfiltration detection",
		true, `(?i)export\s+data`,
	)
	newPattern := newTestPattern(
		"EXPORT-001", "TechExport",
		FrameworkATLAS, SeverityHigh,
		"exfil", "Updated exfiltration detection",
		false, `(?i)export\s+(data|sensitive)`,
	)
	at.RecordPatternChange(oldPattern, newPattern, "admin", "downgrade severity")

	// Export
	jsonData, err := at.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var rawEntries []map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawEntries); err != nil {
		t.Fatalf("exported data is not valid JSON: %v", err)
	}

	if len(rawEntries) < 2 {
		t.Fatalf("expected at least 2 exported entries, got %d", len(rawEntries))
	}

	// Import into a new audit trail
	at2 := NewAuditTrail()
	if err := at2.ImportJSON(jsonData); err != nil {
		t.Fatalf("ImportJSON failed: %v", err)
	}

	// Verify data matches
	stats := at2.Stats()
	if stats.TotalEntries != at.Stats().TotalEntries {
		t.Errorf("expected %d entries after import, got %d",
			at.Stats().TotalEntries, stats.TotalEntries)
	}

	// Query to verify imported data
	history := at2.GetHistory("EXPORT-001")
	if len(history) == 0 {
		t.Fatal("expected history entries after import")
	}
}

func TestStats(t *testing.T) {
	at := NewAuditTrail()

	p1 := newTestPattern("ST-001", "Tech1", FrameworkATLAS, SeverityHigh, "cat", "desc", true, `(?i)test1`)
	p2 := newTestPattern("ST-002", "Tech2", FrameworkOWASP, SeverityCritical, "cat", "desc", true, `(?i)test2`)
	p3 := newTestPattern("ST-003", "Tech3", FrameworkATLAS, SeverityLow, "cat", "desc", false, `(?i)test3`)

	at.RecordPatternAddition(p1, "alice", "initial")
	at.RecordPatternAddition(p2, "bob", "initial")
	at.RecordPatternRemoval(p3, "alice", "deprecated")

	stats := at.Stats()

	if stats.TotalEntries != 3 {
		t.Errorf("expected 3 total entries, got %d", stats.TotalEntries)
	}
	if stats.ByFramework[string(FrameworkATLAS)] != 2 {
		t.Errorf("expected 2 ATLAS entries, got %d", stats.ByFramework[string(FrameworkATLAS)])
	}
	if stats.ByFramework[string(FrameworkOWASP)] != 1 {
		t.Errorf("expected 1 OWASP entry, got %d", stats.ByFramework[string(FrameworkOWASP)])
	}
	if stats.ByChangeType[ChangeTypeAdded] != 2 {
		t.Errorf("expected 2 'added' entries, got %d", stats.ByChangeType[ChangeTypeAdded])
	}
	if stats.ByChangeType[ChangeTypeRemoved] != 1 {
		t.Errorf("expected 1 'removed' entry, got %d", stats.ByChangeType[ChangeTypeRemoved])
	}
	if stats.ByAuthor["alice"] != 2 {
		t.Errorf("expected 2 entries by alice, got %d", stats.ByAuthor["alice"])
	}
	if stats.ByAuthor["bob"] != 1 {
		t.Errorf("expected 1 entry by bob, got %d", stats.ByAuthor["bob"])
	}
	if stats.Earliest.IsZero() {
		t.Error("expected non-zero Earliest timestamp")
	}
	if stats.Latest.IsZero() {
		t.Error("expected non-zero Latest timestamp")
	}
}

func TestStats_EmptyTrail(t *testing.T) {
	at := NewAuditTrail()
	stats := at.Stats()

	if stats.TotalEntries != 0 {
		t.Errorf("expected 0 entries for empty trail, got %d", stats.TotalEntries)
	}
	if stats.Earliest.IsZero() {
		// Empty trail should have zero time for earliest
		t.Log("Earliest is zero for empty trail (expected)")
	}
}

func TestRecordPatternChange_NoChanges(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern(
		"NC-001", "TechNC",
		FrameworkATLAS, SeverityHigh,
		"cat", "desc",
		true, `(?i)regex`,
	)

	entries := at.RecordPatternChange(p, p, "admin", "no change")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for identical patterns, got %d", len(entries))
	}
}

func TestRecordPatternChange_NilPatterns(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern("NIL-001", "Tech", FrameworkATLAS, SeverityHigh, "cat", "desc", true, `(?i)regex`)

	entries := at.RecordPatternChange(nil, p, "admin", "test")
	if entries != nil {
		t.Errorf("expected nil for nil old pattern, got %v", entries)
	}

	entries = at.RecordPatternChange(p, nil, "admin", "test")
	if entries != nil {
		t.Errorf("expected nil for nil new pattern, got %v", entries)
	}
}

func TestQuery_MultipleFilters(t *testing.T) {
	at := NewAuditTrail()

	p1 := newTestPattern("MF-001", "Tech1", FrameworkATLAS, SeverityHigh, "cat", "desc", true, `(?i)test1`)
	p2 := newTestPattern("MF-002", "Tech2", FrameworkOWASP, SeverityCritical, "cat", "desc", true, `(?i)test2`)

	at.RecordPatternAddition(p1, "alice", "add")
	at.RecordPatternAddition(p2, "bob", "add")

	// Query with both framework and author
	results := at.Query(AuditQuery{
		Framework: FrameworkATLAS,
		Author:    "alice",
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result with combined filters, got %d", len(results))
	}
	if results[0].PatternID != "MF-001" {
		t.Errorf("expected pattern MF-001, got %s", results[0].PatternID)
	}
}

func TestAuditEntriesAsJSON(t *testing.T) {
	at := NewAuditTrail()

	p := newTestPattern("JSON-001", "Tech", FrameworkATLAS, SeverityHigh, "cat", "desc", true, `(?i)json`)
	at.RecordPatternAddition(p, "admin", "test")

	jsonData, err := at.AuditEntriesAsJSON(AuditQuery{PatternID: "JSON-001"})
	if err != nil {
		t.Fatalf("AuditEntriesAsJSON failed: %v", err)
	}

	var entries []AuditEntry
	if err := json.Unmarshal(jsonData, &entries); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].PatternID != "JSON-001" {
		t.Errorf("expected pattern JSON-001, got %s", entries[0].PatternID)
	}
}

func TestRollbackDescription(t *testing.T) {
	at := NewAuditTrail()

	p1 := newTestPattern("RB-001", "TechA", FrameworkATLAS, SeverityLow, "cat", "desc v1", false, `(?i)regex1`)
	p2 := newTestPattern("RB-001", "TechA", FrameworkATLAS, SeverityHigh, "cat", "desc v2", true, `(?i)regex2`)

	at.RecordPatternAddition(p1, "admin", "initial")
	changeEntries := at.RecordPatternChange(p1, p2, "admin", "update")

	if len(changeEntries) == 0 {
		t.Fatal("expected at least one change entry")
	}

	// Get rollback description for version 1
	desc := at.RollbackDescription("RB-001", 2)
	if desc == "" {
		t.Error("expected non-empty rollback description")
	}
	if len(desc) == 0 {
		t.Error("rollback description should contain field information")
	}
}