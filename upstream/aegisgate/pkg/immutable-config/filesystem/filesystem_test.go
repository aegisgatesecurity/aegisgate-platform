package filesystem

import (
	"os"
	"testing"
	"time"

	immutableconfig "github.com/aegisgatesecurity/aegisgate/pkg/immutable-config"
)

func TestNewImmutableFilesystem(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if fs == nil {
		t.Error("Expected filesystem to be created")
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if err := fs.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Create and save config
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{
		"setting1": "value1",
		"setting2": 42,
	}, map[string]string{
		"author": "test",
	})

	version, err := fs.Save(config)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	if version.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", version.Version)
	}

	// Load the config
	loaded, err := fs.Load("v1.0")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if loaded.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", loaded.Version)
	}

	if loaded.Data["setting1"] != "value1" {
		t.Errorf("Expected setting1=value1, got %v", loaded.Data["setting1"])
	}
}

func TestSeal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if err := fs.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Initially not sealed
	if fs.IsSealed() {
		t.Error("Expected filesystem to not be sealed initially")
	}

	// Seal it
	if err := fs.Seal(); err != nil {
		t.Fatalf("Failed to seal: %v", err)
	}

	// Now should be sealed
	if !fs.IsSealed() {
		t.Error("Expected filesystem to be sealed")
	}

	// Attempt to save should fail
	config := immutableconfig.NewConfigData("v2.0", nil, nil)
	_, err = fs.Save(config)
	if err == nil {
		t.Error("Expected error when saving to sealed filesystem")
	}

	// Unseal
	if err := fs.Unseal(); err != nil {
		t.Fatalf("Failed to unseal: %v", err)
	}

	if fs.IsSealed() {
		t.Error("Expected filesystem to not be sealed after unseal")
	}
}

func TestSnapshot(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if err := fs.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Save some configs
	for i := 1; i <= 3; i++ {
		version := string(rune('v'+i-1)) + "." + string(rune('0'+i))
		config := immutableconfig.NewConfigData(
			version,
			map[string]interface{}{"count": i},
			nil,
		)
		fs.Save(config)
	}

	// Create snapshot
	snapshot, err := fs.CreateSnapshot("test-snapshot", "Test snapshot")
	if err != nil {
		t.Fatalf("Failed to create snapshot: %v", err)
	}

	if snapshot.Name != "test-snapshot" {
		t.Errorf("Expected snapshot name 'test-snapshot', got %s", snapshot.Name)
	}

	// List snapshots
	snapshots, err := fs.ListSnapshots()
	if err != nil {
		t.Fatalf("Failed to list snapshots: %v", err)
	}

	if len(snapshots) != 1 {
		t.Errorf("Expected 1 snapshot, got %d", len(snapshots))
	}

	// Verify snapshot integrity
	verified, err := fs.snapshotMgr.Verify(snapshot.ID)
	if err != nil {
		t.Fatalf("Failed to verify snapshot: %v", err)
	}

	if !verified {
		t.Error("Snapshot integrity verification failed")
	}
}

func TestWAL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if err := fs.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Save config
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"test": "value"}, nil)
	fs.Save(config)

	// Get WAL stats
	stats := fs.GetWALStats()

	if stats["committed"] != 1 {
		t.Errorf("Expected 1 committed entry, got %d", stats["committed"])
	}
}

func TestAuditLog(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if err := fs.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Save config
	config := immutableconfig.NewConfigData("v1.0", nil, nil)
	fs.Save(config)

	// Load config
	fs.Load("v1.0")

	// Get audit log
	log := fs.GetAuditLog()

	// Should have at least 2 entries (save + load)
	if len(log) < 2 {
		t.Errorf("Expected at least 2 audit entries, got %d", len(log))
	}
}

func TestCheckpoint(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if err := fs.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Save configs
	for i := 1; i <= 3; i++ {
		version := string(rune('v'+i-1)) + "." + string(rune('0'+i))
		fs.Save(immutableconfig.NewConfigData(
			version,
			map[string]interface{}{"version": i},
			nil,
		))
	}

	// Export checkpoint
	checkpoint, err := fs.ExportCheckpoint()
	if err != nil {
		t.Fatalf("Failed to export checkpoint: %v", err)
	}

	if len(checkpoint.Versions) < 1 {
		t.Error("Expected at least 1 version in checkpoint")
	}

	// Export to JSON
	jsonStr, err := checkpoint.ToJSON()
	if err != nil {
		t.Fatalf("Failed to export checkpoint to JSON: %v", err)
	}

	if jsonStr == "" {
		t.Error("Expected non-empty JSON string")
	}
}

func TestIntegrityVerification(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if err := fs.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Save config
	config := immutableconfig.NewConfigData("v1.0", map[string]interface{}{"test": "value"}, nil)
	fs.Save(config)

	// Verify integrity
	results, err := fs.VerifyIntegrity()
	if err != nil {
		t.Fatalf("Failed to verify integrity: %v", err)
	}

	for version, verified := range results {
		if !verified {
			t.Errorf("Integrity verification failed for version %s", version)
		}
	}
}

func TestLoadLatest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "immutable-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &FilesystemConfig{
		BasePath:        tmpDir,
		MaxVersions:     10,
		MaxAuditEntries: 100,
		EnableWatch:     false,
	}

	fs, err := NewImmutableFilesystem(cfg)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}
	defer fs.Close()

	if err := fs.Initialize(); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Save multiple configs
	for i := 1; i <= 3; i++ {
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
		config := immutableconfig.NewConfigData(
			string(rune('v'+i-1))+"."+string(rune('0'+i)),
			map[string]interface{}{"count": i},
			nil,
		)
		fs.Save(config)
	}

	// Load latest
	latest, err := fs.LoadLatest()
	if err != nil {
		t.Fatalf("Failed to load latest: %v", err)
	}

	if latest == nil {
		t.Error("Expected latest config to be returned")
	}
}
