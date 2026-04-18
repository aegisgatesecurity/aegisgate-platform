package integrity

import (
	"testing"
)

func TestComputeHash(t *testing.T) {
	checker := NewIntegrityChecker()

	data := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	metadata := map[string]string{
		"author": "test",
	}

	hash, err := checker.ComputeHash("v1.0", data, metadata)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if hash == "" {
		t.Errorf("Expected non-empty hash")
	}

	// Test that same data produces same hash
	hash2, err := checker.ComputeHash("v1.0", data, metadata)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if hash != hash2 {
		t.Errorf("Same data should produce same hash")
	}
}

func TestVerify(t *testing.T) {
	checker := NewIntegrityChecker()

	data := map[string]interface{}{
		"key": "value",
	}

	metadata := map[string]string{}

	hash, err := checker.ComputeHash("v1.0", data, metadata)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	verified, err := checker.Verify(hash, "v1.0", data, metadata)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !verified {
		t.Errorf("Expected verified to be true")
	}
}

func TestVerifyMismatch(t *testing.T) {
	checker := NewIntegrityChecker()

	data := map[string]interface{}{
		"key": "value",
	}

	metadata := map[string]string{}

	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"

	verified, err := checker.Verify(wrongHash, "v1.0", data, metadata)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if verified {
		t.Errorf("Expected verified to be false for mismatched hash")
	}
}

func TestNewIntegrityError(t *testing.T) {
	err := NewIntegrityError("test message", "hash1", "hash2")

	if err.Error() != "test message" {
		t.Errorf("Expected error message 'test message', got %s", err.Error())
	}
}

func TestIntegrityErrorString(t *testing.T) {
	err := NewIntegrityError("test message", "hash1", "hash2")

	str := err.Error()
	if str != "test message" {
		t.Errorf("Expected 'test message', got %s", str)
	}
}

func TestEmptyDataHash(t *testing.T) {
	checker := NewIntegrityChecker()

	data := map[string]interface{}{}
	metadata := map[string]string{}

	hash, err := checker.ComputeHash("v1.0", data, metadata)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if hash == "" {
		t.Errorf("Expected non-empty hash for empty data")
	}
}

func TestNilDataHash(t *testing.T) {
	checker := NewIntegrityChecker()

	hash, err := checker.ComputeHash("v1.0", nil, nil)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if hash == "" {
		t.Errorf("Expected non-empty hash for nil data")
	}
}

func TestVersionHashVariation(t *testing.T) {
	checker := NewIntegrityChecker()

	data := map[string]interface{}{
		"key": "value",
	}

	metadata := map[string]string{}

	hash1, err := checker.ComputeHash("v1.0", data, metadata)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	hash2, err := checker.ComputeHash("v2.0", data, metadata)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Different versions should produce different hashes")
	}
}
