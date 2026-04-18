package wal

import (
	"os"
	"testing"
)

func TestNewWAL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{
		BasePath:   tmpDir,
		MaxEntries: 100,
	}

	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}

	if wal == nil {
		t.Error("Expected WAL to be created")
	}
}

func TestNewWALWithNilOptions(t *testing.T) {
	wal, err := NewWAL(nil)
	if err != nil {
		t.Fatalf("Failed to create WAL with nil options: %v", err)
	}
	defer os.RemoveAll("./wal-data")
	defer wal.Close()

	if wal == nil {
		t.Error("Expected WAL to be created with default options")
	}
}

func TestDefaultWALOptions(t *testing.T) {
	opts := DefaultWALOptions()

	if opts.MaxEntries != 1000 {
		t.Errorf("Expected MaxEntries 1000, got %d", opts.MaxEntries)
	}

	if opts.BasePath != "./wal-data" {
		t.Errorf("Expected BasePath './wal-data', got %s", opts.BasePath)
	}
}

func TestAppend(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	entry, err := wal.Append(EntryTypeSave, "v1.0", map[string]interface{}{"key": "value"}, nil)
	if err != nil {
		t.Fatalf("Failed to append entry: %v", err)
	}

	if entry.ID == "" {
		t.Error("Expected entry to have an ID")
	}

	if entry.Type != EntryTypeSave {
		t.Errorf("Expected type %s, got %s", EntryTypeSave, entry.Type)
	}

	if entry.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", entry.Version)
	}

	if entry.Status != "pending" {
		t.Errorf("Expected status 'pending', got %s", entry.Status)
	}

	if entry.Checksum == "" {
		t.Error("Expected checksum to be generated")
	}
}

func TestAppendWithMetadata(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	metadata := map[string]string{"author": "test"}
	entry, err := wal.Append(EntryTypeSave, "v1.0", nil, metadata)
	if err != nil {
		t.Fatalf("Failed to append entry: %v", err)
	}

	if entry.Metadata["author"] != "test" {
		t.Errorf("Expected author metadata, got %v", entry.Metadata["author"])
	}
}

func TestCommit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	entry, _ := wal.Append(EntryTypeSave, "v1.0", nil, nil)

	err = wal.Commit(entry.ID)
	if err != nil {
		t.Fatalf("Failed to commit entry: %v", err)
	}

	// Verify status changed
	retrieved, _ := wal.Get(entry.ID)
	if retrieved.Status != "committed" {
		t.Errorf("Expected status 'committed', got %s", retrieved.Status)
	}
}

func TestCommitNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	err = wal.Commit("nonexistent")
	if err == nil {
		t.Error("Expected error when committing nonexistent entry")
	}
}

func TestRollback(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	entry, _ := wal.Append(EntryTypeSave, "v1.0", nil, nil)

	err = wal.Rollback(entry.ID)
	if err != nil {
		t.Fatalf("Failed to rollback entry: %v", err)
	}

	// Verify status changed
	retrieved, _ := wal.Get(entry.ID)
	if retrieved.Status != "rolled_back" {
		t.Errorf("Expected status 'rolled_back', got %s", retrieved.Status)
	}
}

func TestRollbackNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	err = wal.Rollback("nonexistent")
	if err == nil {
		t.Error("Expected error when rolling back nonexistent entry")
	}
}

func TestGet(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	entry, _ := wal.Append(EntryTypeSave, "v1.0", nil, nil)

	retrieved, err := wal.Get(entry.ID)
	if err != nil {
		t.Fatalf("Failed to get entry: %v", err)
	}

	if retrieved.ID != entry.ID {
		t.Errorf("Expected ID %s, got %s", entry.ID, retrieved.ID)
	}
}

func TestGetNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	_, err = wal.Get("nonexistent")
	if err == nil {
		t.Error("Expected error when getting nonexistent entry")
	}
}

func TestList(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	// Add entries of different types
	wal.Append(EntryTypeSave, "v1.0", nil, nil)
	wal.Append(EntryTypeDelete, "v0.9", nil, nil)
	wal.Append(EntryTypeSave, "v2.0", nil, nil)

	// List all
	all := wal.List("", "")
	if len(all) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(all))
	}

	// List by type
	saves := wal.List(EntryTypeSave, "")
	if len(saves) != 2 {
		t.Errorf("Expected 2 save entries, got %d", len(saves))
	}

	deletes := wal.List(EntryTypeDelete, "")
	if len(deletes) != 1 {
		t.Errorf("Expected 1 delete entry, got %d", len(deletes))
	}
}

func TestListPending(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	// Add entries
	entry1, _ := wal.Append(EntryTypeSave, "v1.0", nil, nil)
	entry2, _ := wal.Append(EntryTypeSave, "v2.0", nil, nil)
	wal.Commit(entry1.ID)

	// List pending
	pending := wal.ListPending()
	if len(pending) != 1 {
		t.Errorf("Expected 1 pending entry, got %d", len(pending))
	}

	if pending[0].ID != entry2.ID {
		t.Errorf("Expected pending entry to be entry2")
	}
}

func TestListCommitted(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	// Add entries
	entry1, _ := wal.Append(EntryTypeSave, "v1.0", nil, nil)
	wal.Append(EntryTypeSave, "v2.0", nil, nil)
	wal.Commit(entry1.ID)

	committed := wal.ListCommitted()
	if len(committed) != 1 {
		t.Errorf("Expected 1 committed entry, got %d", len(committed))
	}
}

func TestRecover(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}

	// Add and commit entries
	entry1, _ := wal.Append(EntryTypeSave, "v1.0", map[string]interface{}{"key": "value1"}, nil)
	entry2, _ := wal.Append(EntryTypeSave, "v2.0", map[string]interface{}{"key": "value2"}, nil)

	// Add a pending entry (should not be recovered)
	wal.Append(EntryTypeSave, "v3.0", nil, nil)

	// Commit entries
	if err := wal.Commit(entry1.ID); err != nil {
		t.Fatalf("Failed to commit entry1: %v", err)
	}
	if err := wal.Commit(entry2.ID); err != nil {
		t.Fatalf("Failed to commit entry2: %v", err)
	}

	// Track recovered entries
	var recovered []*Entry
	err = wal.Recover(func(entry *Entry) error {
		recovered = append(recovered, entry)
		return nil
	})

	if err != nil {
		t.Fatalf("Recovery failed: %v", err)
	}

	if len(recovered) != 2 {
		t.Errorf("Expected 2 recovered entries, got %d", len(recovered))
	}

	// Verify the recovered entries
	for i, entry := range recovered {
		if entry.Status != "committed" {
			t.Errorf("Recovered entry %d has wrong status: %s", i, entry.Status)
		}
	}

	wal.Close()
}

func TestCompact(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	// Add entries
	entry1, _ := wal.Append(EntryTypeSave, "v1.0", nil, nil)
	entry2, _ := wal.Append(EntryTypeSave, "v2.0", nil, nil)
	wal.Commit(entry1.ID)
	wal.Commit(entry2.ID)

	// Add a pending entry
	entry3, _ := wal.Append(EntryTypeSave, "v3.0", nil, nil)

	// Compact
	err = wal.Compact()
	if err != nil {
		t.Fatalf("Compact failed: %v", err)
	}

	// Only pending entries should remain
	stats := wal.GetStats()
	if stats["total_entries"] != 1 {
		t.Errorf("Expected 1 entry after compact, got %d", stats["total_entries"])
	}

	// Verify pending entry still exists
	_, err = wal.Get(entry3.ID)
	if err != nil {
		t.Error("Expected pending entry to still exist after compact")
	}
}

func TestClear(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	// Add entries
	wal.Append(EntryTypeSave, "v1.0", nil, nil)
	wal.Append(EntryTypeSave, "v2.0", nil, nil)

	// Clear
	err = wal.Clear()
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	stats := wal.GetStats()
	if stats["total_entries"] != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", stats["total_entries"])
	}
}

func TestGetStats(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir, MaxEntries: 100}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	// Add entries with different statuses
	entry1, _ := wal.Append(EntryTypeSave, "v1.0", nil, nil)
	entry2, _ := wal.Append(EntryTypeSave, "v2.0", nil, nil)
	entry3, _ := wal.Append(EntryTypeSave, "v3.0", nil, nil)
	wal.Commit(entry1.ID)
	wal.Commit(entry2.ID)
	wal.Rollback(entry3.ID)
	wal.Append(EntryTypeSave, "v4.0", nil, nil) // pending

	stats := wal.GetStats()

	if stats["total_entries"] != 4 {
		t.Errorf("Expected total_entries 4, got %d", stats["total_entries"])
	}

	if stats["committed"] != 2 {
		t.Errorf("Expected committed 2, got %d", stats["committed"])
	}

	if stats["rolled_back"] != 1 {
		t.Errorf("Expected rolled_back 1, got %d", stats["rolled_back"])
	}

	if stats["pending"] != 1 {
		t.Errorf("Expected pending 1, got %d", stats["pending"])
	}

	if stats["max_entries"] != 100 {
		t.Errorf("Expected max_entries 100, got %d", stats["max_entries"])
	}
}

func TestGetLatestLSN(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}
	wal, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}
	defer wal.Close()

	// Initial LSN should be 0
	if wal.GetLatestLSN() != 0 {
		t.Errorf("Expected initial LSN 0, got %d", wal.GetLatestLSN())
	}

	// Append should increment LSN
	wal.Append(EntryTypeSave, "v1.0", nil, nil)
	if wal.GetLatestLSN() != 1 {
		t.Errorf("Expected LSN 1, got %d", wal.GetLatestLSN())
	}

	wal.Append(EntryTypeSave, "v2.0", nil, nil)
	if wal.GetLatestLSN() != 2 {
		t.Errorf("Expected LSN 2, got %d", wal.GetLatestLSN())
	}
}

func TestWALPersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WALOptions{BasePath: tmpDir}

	// Create WAL and add entries
	wal1, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create WAL: %v", err)
	}

	entry1, _ := wal1.Append(EntryTypeSave, "v1.0", nil, nil)
	wal1.Commit(entry1.ID)
	wal1.Close()

	// Create new WAL instance - should load existing entries
	wal2, err := NewWAL(opts)
	if err != nil {
		t.Fatalf("Failed to create second WAL: %v", err)
	}
	defer wal2.Close()

	// Verify entry was loaded
	retrieved, err := wal2.Get(entry1.ID)
	if err != nil {
		t.Fatalf("Failed to get persisted entry: %v", err)
	}

	if retrieved.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", retrieved.Version)
	}

	if retrieved.Status != "committed" {
		t.Errorf("Expected status committed, got %s", retrieved.Status)
	}
}

func TestEntryTypeConstants(t *testing.T) {
	if EntryTypeSave != "save" {
		t.Errorf("Expected EntryTypeSave to be 'save', got %s", EntryTypeSave)
	}
	if EntryTypeDelete != "delete" {
		t.Errorf("Expected EntryTypeDelete to be 'delete', got %s", EntryTypeDelete)
	}
	if EntryTypeRollback != "rollback" {
		t.Errorf("Expected EntryTypeRollback to be 'rollback', got %s", EntryTypeRollback)
	}
	if EntryTypeSnapshot != "snapshot" {
		t.Errorf("Expected EntryTypeSnapshot to be 'snapshot', got %s", EntryTypeSnapshot)
	}
	if EntryTypeSeal != "seal" {
		t.Errorf("Expected EntryTypeSeal to be 'seal', got %s", EntryTypeSeal)
	}
}
