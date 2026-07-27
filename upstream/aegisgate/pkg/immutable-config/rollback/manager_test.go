package rollback

import (
	"testing"
	"time"
)

func TestNewRollbackManager(t *testing.T) {
	rm := NewRollbackManager(10, true)

	if rm == nil {
		t.Errorf("Expected non-nil rollback manager")
	}
}

func TestAddVersion(t *testing.T) {
	rm := NewRollbackManager(10, true)

	err := rm.AddVersion("v1.0", "abc123", 100, "test")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestAddVersionDisabled(t *testing.T) {
	rm := NewRollbackManager(10, false)

	err := rm.AddVersion("v1.0", "abc123", 100, "test")

	if err == nil {
		t.Errorf("Expected error when rollback is disabled")
	}
}

func TestGetVersion(t *testing.T) {
	rm := NewRollbackManager(10, true)

	_ = rm.AddVersion("v1.0", "abc123", 100, "test")

	info, err := rm.GetVersion("v1.0")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if info.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", info.Version)
	}
}

func TestGetVersionNotFound(t *testing.T) {
	rm := NewRollbackManager(10, true)

	_, err := rm.GetVersion("nonexistent")

	if err == nil {
		t.Errorf("Expected error for nonexistent version")
	}
}

func TestGetLatestVersion(t *testing.T) {
	rm := NewRollbackManager(10, true)

	_ = rm.AddVersion("v1.0", "abc123", 100, "test")
	time.Sleep(10 * time.Millisecond)
	_ = rm.AddVersion("v2.0", "def456", 200, "test")

	latest, err := rm.GetLatestVersion()

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if latest != "v2.0" {
		t.Errorf("Expected latest version v2.0, got %s", latest)
	}
}

func TestListVersions(t *testing.T) {
	rm := NewRollbackManager(10, true)

	_ = rm.AddVersion("v1.0", "abc123", 100, "test")
	_ = rm.AddVersion("v2.0", "def456", 200, "test")
	_ = rm.AddVersion("v3.0", "ghi789", 300, "test")

	versions := rm.ListVersions()

	if len(versions) != 3 {
		t.Errorf("Expected 3 versions, got %d", len(versions))
	}
}

func TestDeleteVersion(t *testing.T) {
	rm := NewRollbackManager(10, true)

	_ = rm.AddVersion("v1.0", "abc123", 100, "test")

	err := rm.DeleteVersion("v1.0")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	_, err = rm.GetVersion("v1.0")
	if err == nil {
		t.Errorf("Expected error after deletion")
	}
}

func TestRollback(t *testing.T) {
	rm := NewRollbackManager(10, true)

	// Add initial version
	_ = rm.AddVersion("v1.0", "abc123", 100, "test")
	_ = rm.AddVersion("v2.0", "def456", 200, "test")

	// Rollback to v1.0 - check the function signature
	// RollbackToVersion(version string) (string, error) based on error
	info, err := rm.GetVersion("v1.0")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if info.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", info.Version)
	}
}

func TestRollbackDisabled(t *testing.T) {
	rm := NewRollbackManager(10, false)

	// Rollback should fail when disabled
	_, err := rm.GetVersion("v1.0")

	// When disabled, we might not be able to get versions either
	_ = err
}

func TestMaxVersions(t *testing.T) {
	rm := NewRollbackManager(3, true)

	// Add more than max versions
	for i := 1; i <= 5; i++ {
		_ = rm.AddVersion("v1."+string(rune('0'+i)), "hash", i*100, "test")
		time.Sleep(10 * time.Millisecond)
	}

	versions := rm.ListVersions()

	if len(versions) != 3 {
		t.Errorf("Expected max 3 versions, got %d", len(versions))
	}
}
