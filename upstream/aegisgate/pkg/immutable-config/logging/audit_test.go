package logging

import (
	"testing"
	"time"
)

func TestNewAuditLogger(t *testing.T) {
	logger := NewAuditLogger(100)

	if logger == nil {
		t.Errorf("Expected non-nil audit logger")
	}
}

func TestLog(t *testing.T) {
	logger := NewAuditLogger(100)

	entry := logger.Log(
		"config_save",
		"v1.0",
		"save",
		"Test entry",
		"abc123",
		"signature",
	)

	if entry == nil {
		t.Errorf("Expected non-nil entry")
	}

	if entry.EventType != "config_save" {
		t.Errorf("Expected event_type config_save, got %s", entry.EventType)
	}

	if entry.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", entry.Version)
	}
}

func TestGetEntries(t *testing.T) {
	logger := NewAuditLogger(100)

	logger.Log("test1", "v1.0", "op1", "detail1", "hash1", "sig1")
	logger.Log("test2", "v2.0", "op2", "detail2", "hash2", "sig2")

	entries := logger.GetEntries()

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}
}

func TestGetLatestEntry(t *testing.T) {
	logger := NewAuditLogger(100)

	logger.Log("test1", "v1.0", "op1", "detail1", "hash1", "sig1")
	latest1 := logger.GetLatestEntry()

	logger.Log("test2", "v2.0", "op2", "detail2", "hash2", "sig2")
	latest2 := logger.GetLatestEntry()

	if latest1 == latest2 {
		t.Errorf("Latest entries should be different")
	}

	if latest2.EventType != "test2" {
		t.Errorf("Expected latest event type test2, got %s", latest2.EventType)
	}
}

func TestGetEntriesByType(t *testing.T) {
	logger := NewAuditLogger(100)

	logger.Log("type1", "v1.0", "op1", "detail1", "hash1", "sig1")
	logger.Log("type2", "v2.0", "op2", "detail2", "hash2", "sig2")
	logger.Log("type1", "v3.0", "op3", "detail3", "hash3", "sig3")

	entries := logger.GetEntriesByType("type1")

	if len(entries) != 2 {
		t.Errorf("Expected 2 type1 entries, got %d", len(entries))
	}
}

func TestGetEntriesByVersion(t *testing.T) {
	logger := NewAuditLogger(100)

	logger.Log("type1", "v1.0", "op1", "detail1", "hash1", "sig1")
	logger.Log("type2", "v2.0", "op2", "detail2", "hash2", "sig2")
	logger.Log("type1", "v1.0", "op3", "detail3", "hash3", "sig3")

	entries := logger.GetEntriesByVersion("v1.0")

	if len(entries) != 2 {
		t.Errorf("Expected 2 v1.0 entries, got %d", len(entries))
	}
}

func TestMaxEntries(t *testing.T) {
	logger := NewAuditLogger(2)

	logger.Log("test1", "v1.0", "op1", "detail1", "hash1", "sig1")
	logger.Log("test2", "v2.0", "op2", "detail2", "hash2", "sig2")
	logger.Log("test3", "v3.0", "op3", "detail3", "hash3", "sig3")

	entries := logger.GetEntries()

	if len(entries) != 2 {
		t.Errorf("Expected max 2 entries, got %d", len(entries))
	}
}

func TestAuditEntryString(t *testing.T) {
	logger := NewAuditLogger(100)

	entry := logger.Log("test", "v1.0", "op", "detail", "abc123def456", "sig")

	str := entry.String()
	if str == "" {
		t.Errorf("Expected non-empty string")
	}
}

func TestAuditEntryTimestamp(t *testing.T) {
	logger := NewAuditLogger(100)

	before := time.Now()
	logger.Log("test", "v1.0", "op", "detail", "hash", "sig")
	after := time.Now()

	entries := logger.GetEntries()
	if len(entries) > 0 {
		entryTime := entries[0].Timestamp
		if entryTime.Before(before) || entryTime.After(after) {
			t.Errorf("Entry timestamp should be between %v and %v", before, after)
		}
	}
}

func TestAllAuditEntryTypes(t *testing.T) {
	logger := NewAuditLogger(100)

	entryTypes := []string{
		EventConfigSave,
		EventConfigLoad,
		EventConfigRollback,
		EventConfigDelete,
		EventIntegrityFail,
		EventSignatureFail,
	}

	for _, eventType := range entryTypes {
		logger.Log(eventType, "v1.0", "op", "detail", "hash", "sig")
	}

	entries := logger.GetEntries()
	if len(entries) != len(entryTypes) {
		t.Errorf("Expected %d entries, got %d", len(entryTypes), len(entries))
	}
}
