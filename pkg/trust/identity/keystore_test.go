// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Keystore Tests
// =========================================================================

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestKeystore_New(t *testing.T) {
	ks := New()
	if ks == nil {
		t.Fatal("New returned nil")
	}
}

func TestKeystore_StoreAndGet(t *testing.T) {
	ks := New()

	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	agentID := "agent-123"

	err = ks.Store(agentID, privateKey)
	if err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	retrieved, err := ks.Get(agentID)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Retrieved key is nil")
	}

	if !keysEqual(privateKey, retrieved) {
		t.Error("Retrieved key does not match stored key")
	}
}

func TestKeystore_GetNotFound(t *testing.T) {
	ks := New()

	_, err := ks.Get("nonexistent-agent")
	if err == nil {
		t.Error("Expected error for nonexistent agent, got nil")
	}
}

func TestKeystore_Delete(t *testing.T) {
	ks := New()

	privateKey, _, _ := GenerateKeyPair()
	agentID := "agent-456"

	_ = ks.Store(agentID, privateKey)

	err := ks.Delete(agentID)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	_, err = ks.Get(agentID)
	if err == nil {
		t.Error("Expected error after deletion, got nil")
	}
}

func TestKeystore_DeleteNotFound(t *testing.T) {
	ks := New()

	err := ks.Delete("nonexistent-agent")
	if err != nil {
		t.Errorf("Delete should not error for nonexistent agent: %v", err)
	}
}

func TestKeystore_Exists(t *testing.T) {
	ks := New()

	privateKey, _, _ := GenerateKeyPair()
	agentID := "agent-789"

	if ks.Exists(agentID) {
		t.Error("Exists returned true for nonexistent key")
	}

	_ = ks.Store(agentID, privateKey)

	if !ks.Exists(agentID) {
		t.Error("Exists returned false for existing key")
	}
}

func TestExportPEM(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()

	pemStr, err := ExportPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export PEM: %v", err)
	}

	if len(pemStr) == 0 {
		t.Error("Exported PEM data is empty")
	}

	if len(pemStr) < 50 {
		t.Error("PEM data seems too short")
	}
}

func TestImportPEM(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()

	pemStr, _ := ExportPEM(privateKey)

	importedKey, err := ImportPEM(pemStr)
	if err != nil {
		t.Fatalf("Failed to import PEM: %v", err)
	}

	if !keysEqual(privateKey, importedKey) {
		t.Error("Imported key does not match original")
	}
}

func TestImportPEM_Invalid(t *testing.T) {
	_, err := ImportPEM("invalid pem data")
	if err == nil {
		t.Error("Expected error for invalid PEM, got nil")
	}
}

func TestKeystore_StoreDuplicate(t *testing.T) {
	ks := New()

	privateKey1, _, _ := GenerateKeyPair()
	privateKey2, _, _ := GenerateKeyPair()

	agentID := "agent-dup"

	_ = ks.Store(agentID, privateKey1)
	_ = ks.Store(agentID, privateKey2)

	retrieved, _ := ks.Get(agentID)
	if !keysEqual(privateKey2, retrieved) {
		t.Error("Duplicate store should overwrite with new key")
	}
}

// Helper function to compare ECDSA keys
func keysEqual(a, b *ecdsa.PrivateKey) bool {
	if a.Curve != b.Curve {
		return false
	}
	if a.X.Cmp(b.X) != 0 || a.Y.Cmp(b.Y) != 0 {
		return false
	}
	return true
}

// Helper to create a keypair for testing
func generateTestKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
