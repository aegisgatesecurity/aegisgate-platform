package secrets

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestNewEnvProvider(t *testing.T) {
	provider := NewEnvProvider()
	if provider == nil {
		t.Fatal("NewEnvProvider() returned nil")
	}

	if provider.prefix != "" {
		t.Errorf("NewEnvProvider() prefix = %s, want empty", provider.prefix)
	}
}

func TestEnvProvider_WithPrefix(t *testing.T) {
	provider := NewEnvProvider().WithPrefix("TEST_")
	if provider.prefix != "TEST_" {
		t.Errorf("WithPrefix() prefix = %s, want TEST_", provider.prefix)
	}
}

func TestEnvProvider_Get(t *testing.T) {
	// Set up test environment variable
	_ = os.Setenv("TEST_SECRET", "secretvalue")
	defer func() { _ = os.Unsetenv("TEST_SECRET") }()

	provider := NewEnvProvider()
	ctx := context.Background()

	// Test getting existing secret
	secret, err := provider.Get(ctx, "TEST_SECRET")
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if secret.Value != "secretvalue" {
		t.Errorf("Get() Value = %v, want secretvalue", secret.Value)
	}
	if secret.Metadata["source"] != "env" {
		t.Errorf("Get() Metadata[source] = %v, want env", secret.Metadata["source"])
	}

	// Test getting non-existent secret
	_, err = provider.Get(ctx, "NONEXISTENT_SECRET")
	if err == nil {
		t.Error("Get() should error for non-existent secret")
	}
}

func TestEnvProvider_Get_WithPrefix(t *testing.T) {
	_ = os.Setenv("MYAPP_DB_PASSWORD", "dbpass123")
	defer func() { _ = os.Unsetenv("MYAPP_DB_PASSWORD") }()

	provider := NewEnvProvider().WithPrefix("MYAPP_")
	ctx := context.Background()

	secret, err := provider.Get(ctx, "DB_PASSWORD")
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if secret.Value != "dbpass123" {
		t.Errorf("Get() Value = %v, want dbpass123", secret.Value)
	}
}

func TestEnvProvider_Set(t *testing.T) {
	provider := NewEnvProvider()
	ctx := context.Background()

	secret := Secret{Value: "test"}
	err := provider.Set(ctx, "key", secret)
	if err == nil {
		t.Error("Set() should error - env provider is read-only")
	}
}

func TestEnvProvider_Delete(t *testing.T) {
	provider := NewEnvProvider()
	ctx := context.Background()

	err := provider.Delete(ctx, "key")
	if err == nil {
		t.Error("Delete() should error - env provider is read-only")
	}
}

func TestEnvProvider_List(t *testing.T) {
	// Set up test variables
	_ = os.Setenv("APP_VAR1", "value1")
	os.Setenv("APP_VAR2", "value2")
	defer func() { _ = os.Unsetenv("APP_VAR1") }()
	defer os.Unsetenv("APP_VAR2")

	provider := NewEnvProvider()
	ctx := context.Background()

	keys, err := provider.List(ctx)
	if err != nil {
		t.Errorf("List() error = %v", err)
	}

	// Should include our test vars and possibly others
	foundVar1 := false
	foundVar2 := false
	for _, key := range keys {
		if key == "APP_VAR1" {
			foundVar1 = true
		}
		if key == "APP_VAR2" {
			foundVar2 = true
		}
	}

	if !foundVar1 || !foundVar2 {
		t.Errorf("List() missing test vars. Found VAR1: %v, VAR2: %v", foundVar1, foundVar2)
	}
}

func TestEnvProvider_List_WithPrefix(t *testing.T) {
	os.Setenv("PROD_DB_HOST", "prodhost")
	os.Setenv("PROD_DB_PORT", "5432")
	os.Setenv("DEV_DB_HOST", "devhost")
	defer os.Unsetenv("PROD_DB_HOST")
	defer os.Unsetenv("PROD_DB_PORT")
	defer os.Unsetenv("DEV_DB_HOST")

	provider := NewEnvProvider().WithPrefix("PROD_")
	ctx := context.Background()

	keys, err := provider.List(ctx)
	if err != nil {
		t.Errorf("List() error = %v", err)
	}

	// Should only return PROD_ prefixed vars without the prefix
	foundHost := false
	foundPort := false
	for _, key := range keys {
		if key == "DB_HOST" {
			foundHost = true
		}
		if key == "DB_PORT" {
			foundPort = true
		}
		// Should NOT contain raw env var names
		if strings.HasPrefix(key, "PROD_") {
			t.Errorf("List() returned key with prefix: %s", key)
		}
	}

	if !foundHost || !foundPort {
		t.Errorf("List() missing keys. Host: %v, Port: %v", foundHost, foundPort)
	}
}

func TestEnvProvider_Exists(t *testing.T) {
	os.Setenv("EXISTING_VAR", "exists")
	defer os.Unsetenv("EXISTING_VAR")

	provider := NewEnvProvider()
	ctx := context.Background()

	if !provider.Exists(ctx, "EXISTING_VAR") {
		t.Error("Exists() should return true for existing var")
	}

	if provider.Exists(ctx, "NONEXISTENT_VAR") {
		t.Error("Exists() should return false for nonexistent var")
	}
}

func TestEnvProvider_Close(t *testing.T) {
	provider := NewEnvProvider()
	if err := provider.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestEnvProvider_Health(t *testing.T) {
	provider := NewEnvProvider()
	ctx := context.Background()

	if err := provider.Health(ctx); err != nil {
		t.Errorf("Health() error = %v", err)
	}
}

func TestEnvProvider_Name(t *testing.T) {
	provider := NewEnvProvider()
	if provider.Name() != "env" {
		t.Errorf("Name() = %s, want env", provider.Name())
	}
}
