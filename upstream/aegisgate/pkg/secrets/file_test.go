package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewFileProvider(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "test_secrets.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	if provider.Name() != "file" {
		t.Errorf("Name() = %s, want file", provider.Name())
	}
}

func TestFileProvider_Set_Get(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "secrets.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Test Set
	secret := Secret{
		Value:    "mysecretvalue",
		Metadata: map[string]string{"type": "password"},
	}

	err = provider.Set(ctx, "db_password", secret)
	if err != nil {
		t.Errorf("Set() error = %v", err)
	}

	// Test Get
	got, err := provider.Get(ctx, "db_password")
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if got.Value != "mysecretvalue" {
		t.Errorf("Get() Value = %v", got.Value)
	}
}

func TestFileProvider_Get_NonExistent(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "secrets.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	_, err = provider.Get(ctx, "nonexistent")
	if err == nil {
		t.Error("Get() should error for non-existent key")
	}
}

func TestFileProvider_Delete(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "secrets.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Set then delete
	secret := Secret{Value: "todelete"}
	_ = provider.Set(ctx, "temp", secret)

	err = provider.Delete(ctx, "temp")
	if err != nil {
		t.Errorf("Delete() error = %v", err)
	}

	// Verify deleted
	_, err = provider.Get(ctx, "temp")
	if err == nil {
		t.Error("Get() should error after deletion")
	}
}

func TestFileProvider_List(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "secrets.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Add some secrets
	provider.Set(ctx, "key1", Secret{Value: "v1"})
	provider.Set(ctx, "key2", Secret{Value: "v2"})
	provider.Set(ctx, "key3", Secret{Value: "v3"})

	keys, err := provider.List(ctx)
	if err != nil {
		t.Errorf("List() error = %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("List() returned %d keys, want 3", len(keys))
	}
}

func TestFileProvider_Exists(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "secrets.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	provider.Set(ctx, "exists", Secret{Value: "yes"})

	if !provider.Exists(ctx, "exists") {
		t.Error("Exists() should return true")
	}

	if provider.Exists(ctx, "notexists") {
		t.Error("Exists() should return false")
	}
}

func TestFileProvider_Load_ExistingFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "existing.json")

	// Pre-populate file
	data := `{"preexisting": {"Value": "oldvalue"}}`
	os.WriteFile(filePath, []byte(data), 0600)

	config := &FileConfig{Path: filePath}
	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()
	secret, err := provider.Get(ctx, "preexisting")
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if secret.Value != "oldvalue" {
		t.Errorf("Get() Value = %v", secret.Value)
	}
}

func TestFileProvider_Persistence(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "persist.json")

	// Create provider and add secret
	config := &FileConfig{Path: filePath}
	provider1, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}

	ctx := context.Background()
	provider1.Set(ctx, "persisted", Secret{Value: "survives"})
	provider1.Close()

	// Create new provider, should load existing file
	provider2, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer provider2.Close()

	secret, err := provider2.Get(ctx, "persisted")
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if secret.Value != "survives" {
		t.Errorf("Get() Value = %v", secret.Value)
	}
}

func TestFileProvider_Health(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "health.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()
	if err := provider.Health(ctx); err != nil {
		t.Errorf("Health() error = %v", err)
	}
}

func TestFileProvider_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "concurrent.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	done := make(chan bool, 20)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(id int) {
			key := fmt.Sprintf("key%d", id)
			provider.Set(ctx, key, Secret{Value: "val"})
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(id int) {
			provider.List(ctx)
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		if received(done) != true {
			t.Error("Concurrent operation failed")
		}
	}

	// Verify data integrity
	keys, _ := provider.List(ctx)
	if len(keys) < 10 {
		t.Errorf("Concurrent writes incomplete: %d keys", len(keys))
	}
}

func TestFileProvider_Timestamps(t *testing.T) {
	tempDir := t.TempDir()
	config := &FileConfig{
		Path: filepath.Join(tempDir, "timestamps.json"),
	}

	provider, err := NewFileProvider(config)
	if err != nil {
		t.Fatalf("NewFileProvider() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	beforeSet := time.Now().UTC()
	secret := Secret{Value: "test"}
	provider.Set(ctx, "timestamped", secret)
	afterSet := time.Now().UTC()

	got, _ := provider.Get(ctx, "timestamped")

	if got.CreatedAt.Before(beforeSet) || got.CreatedAt.After(afterSet) {
		t.Error("CreatedAt timestamp out of range")
	}

	if got.UpdatedAt.Before(beforeSet) || got.UpdatedAt.After(afterSet) {
		t.Error("UpdatedAt timestamp out of range")
	}
}

func received(ch <-chan bool) bool {
	return <-ch
}
