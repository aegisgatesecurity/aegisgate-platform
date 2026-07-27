package snapshot

import (
	"os"
	"testing"

	immutableconfig "github.com/aegisgatesecurity/aegisgate/pkg/immutable-config"
)

// mockProvider implements immutableconfig.Provider for testing
type mockProvider struct {
	configs  map[string]*immutableconfig.ConfigData
	versions []*immutableconfig.ConfigVersion
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		configs:  make(map[string]*immutableconfig.ConfigData),
		versions: make([]*immutableconfig.ConfigVersion, 0),
	}
}

func (m *mockProvider) Initialize() error {
	return nil
}

func (m *mockProvider) Load(version string) (*immutableconfig.ConfigData, error) {
	config, exists := m.configs[version]
	if !exists {
		return nil, nil
	}
	return config, nil
}

func (m *mockProvider) Save(config *immutableconfig.ConfigData) (*immutableconfig.ConfigVersion, error) {
	m.configs[config.Version] = config
	version := immutableconfig.NewConfigVersion(config.Version, "test-hash")
	m.versions = append(m.versions, version)
	return version, nil
}

func (m *mockProvider) ListVersions() ([]*immutableconfig.ConfigVersion, error) {
	return m.versions, nil
}

func (m *mockProvider) Close() error {
	return nil
}

func TestNewSnapshotManager(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	if sm == nil {
		t.Error("Expected snapshot manager to be created")
	}
}

func TestCreateSnapshot(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()

	// Add some configs
	for i := 1; i <= 3; i++ {
		version := string(rune('v')) + "." + string(rune('0'+i))
		config := immutableconfig.NewConfigData(version, map[string]interface{}{"count": i}, nil)
		mock.Save(config)
	}

	opts := &SnapshotOptions{
		Name:        "test-snapshot",
		Description: "Test snapshot description",
		Metadata:    map[string]string{"author": "test"},
	}

	snapshot, err := sm.Create(mock, opts)
	if err != nil {
		t.Fatalf("Failed to create snapshot: %v", err)
	}

	if snapshot.Name != "test-snapshot" {
		t.Errorf("Expected name 'test-snapshot', got %s", snapshot.Name)
	}

	if snapshot.Description != "Test snapshot description" {
		t.Errorf("Expected description, got %s", snapshot.Description)
	}

	if snapshot.Checksum == "" {
		t.Error("Expected checksum to be generated")
	}

	if len(snapshot.Configs) != 3 {
		t.Errorf("Expected 3 configs, got %d", len(snapshot.Configs))
	}
}

func TestGetSnapshot(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	mock.Save(config)

	snapshot, _ := sm.Create(mock, &SnapshotOptions{Name: "test"})

	// Get the snapshot
	retrieved, err := sm.Get(snapshot.ID)
	if err != nil {
		t.Fatalf("Failed to get snapshot: %v", err)
	}

	if retrieved.ID != snapshot.ID {
		t.Errorf("Expected ID %s, got %s", snapshot.ID, retrieved.ID)
	}
}

func TestGetSnapshotNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	_, err = sm.Get("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent snapshot")
	}
}

func TestListSnapshots(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()
	config := immutableconfig.NewConfigData("v1.0", nil, nil)
	mock.Save(config)

	// Create multiple snapshots
	sm.Create(mock, &SnapshotOptions{Name: "snapshot1"})
	sm.Create(mock, &SnapshotOptions{Name: "snapshot2"})
	sm.Create(mock, &SnapshotOptions{Name: "snapshot3"})

	snapshots, err := sm.List()
	if err != nil {
		t.Fatalf("Failed to list snapshots: %v", err)
	}

	if len(snapshots) != 3 {
		t.Errorf("Expected 3 snapshots, got %d", len(snapshots))
	}

	// Should be sorted newest first
	for i := 0; i < len(snapshots)-1; i++ {
		if snapshots[i].Created.Before(snapshots[i+1].Created) {
			t.Error("Snapshots should be sorted by creation time (newest first)")
		}
	}
}

func TestDeleteSnapshot(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()
	config := immutableconfig.NewConfigData("v1.0", nil, nil)
	mock.Save(config)

	snapshot, _ := sm.Create(mock, &SnapshotOptions{Name: "test"})

	// Delete snapshot
	err = sm.Delete(snapshot.ID)
	if err != nil {
		t.Fatalf("Failed to delete snapshot: %v", err)
	}

	// Verify it's gone
	_, err = sm.Get(snapshot.ID)
	if err == nil {
		t.Error("Expected error when getting deleted snapshot")
	}
}

func TestDeleteSnapshotNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	err = sm.Delete("nonexistent")
	if err == nil {
		t.Error("Expected error when deleting nonexistent snapshot")
	}
}

func TestVerifySnapshot(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	mock.Save(config)

	snapshot, _ := sm.Create(mock, &SnapshotOptions{Name: "test"})

	// Verify snapshot
	verified, err := sm.Verify(snapshot.ID)
	if err != nil {
		t.Fatalf("Failed to verify snapshot: %v", err)
	}

	if !verified {
		t.Error("Expected snapshot to be verified")
	}
}

func TestVerifySnapshotNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	_, err = sm.Verify("nonexistent")
	if err == nil {
		t.Error("Expected error when verifying nonexistent snapshot")
	}
}

func TestRestoreSnapshot(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	mock.Save(config)

	snapshot, _ := sm.Create(mock, &SnapshotOptions{Name: "test"})

	// Create new mock provider for restore
	restoreMock := newMockProvider()

	// Restore snapshot
	err = sm.Restore(snapshot.ID, restoreMock)
	if err != nil {
		t.Fatalf("Failed to restore snapshot: %v", err)
	}

	// Verify restored data
	restored, err := restoreMock.Load("v1.0")
	if err != nil {
		t.Fatalf("Failed to load restored config: %v", err)
	}

	if restored == nil {
		t.Fatal("Expected restored config to exist")
	}

	if restored.Data["key"] != "value" {
		t.Errorf("Expected key=value, got %v", restored.Data["key"])
	}
}

func TestRestoreSnapshotNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()

	err = sm.Restore("nonexistent", mock)
	if err == nil {
		t.Error("Expected error when restoring nonexistent snapshot")
	}
}

func TestGetChecksum(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()
	config := immutableconfig.NewConfigData("v1.0", nil, nil)
	mock.Save(config)

	snapshot, _ := sm.Create(mock, &SnapshotOptions{Name: "test"})

	checksum, err := sm.GetChecksum(snapshot.ID)
	if err != nil {
		t.Fatalf("Failed to get checksum: %v", err)
	}

	if checksum == "" {
		t.Error("Expected non-empty checksum")
	}

	if checksum != snapshot.Checksum {
		t.Errorf("Expected checksum %s, got %s", snapshot.Checksum, checksum)
	}
}

func TestSnapshotPersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create first manager and snapshot
	sm1, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create first snapshot manager: %v", err)
	}

	mock := newMockProvider()
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"key": "value"}, nil)
	mock.Save(config)

	snapshot1, _ := sm1.Create(mock, &SnapshotOptions{Name: "persisted-test"})

	// Create second manager - should load existing snapshots
	sm2, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create second snapshot manager: %v", err)
	}

	// Verify snapshot was loaded
	snapshot2, err := sm2.Get(snapshot1.ID)
	if err != nil {
		t.Fatalf("Failed to load persisted snapshot: %v", err)
	}

	if snapshot2.Name != "persisted-test" {
		t.Errorf("Expected name 'persisted-test', got %s", snapshot2.Name)
	}

	// Verify configs were loaded
	if len(snapshot2.Configs) != 1 {
		t.Errorf("Expected 1 config in snapshot, got %d", len(snapshot2.Configs))
	}
}

func TestSnapshotWithMetadata(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "snapshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := NewSnapshotManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create snapshot manager: %v", err)
	}

	mock := newMockProvider()
	config := immutableconfig.NewConfigData("v1.0", nil, nil)
	mock.Save(config)

	metadata := map[string]string{
		"author":  "test-user",
		"purpose": "testing",
	}

	snapshot, err := sm.Create(mock, &SnapshotOptions{
		Name:     "with-metadata",
		Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("Failed to create snapshot: %v", err)
	}

	if snapshot.Metadata["author"] != "test-user" {
		t.Errorf("Expected author metadata, got %v", snapshot.Metadata["author"])
	}

	if snapshot.Metadata["purpose"] != "testing" {
		t.Errorf("Expected purpose metadata, got %v", snapshot.Metadata["purpose"])
	}
}
