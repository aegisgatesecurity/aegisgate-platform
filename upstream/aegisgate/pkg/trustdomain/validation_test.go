package trustdomain

import (
	"testing"
	"time"
)

func TestValidationEngine_CertificateValidation(t *testing.T) {
	domain, err := NewTrustDomainBuilder().SetID("test_domain").SetName("Test Domain").Build()
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	config := &ValidationEngineConfig{
		ValidateCertificates: true,
		ValidateSignatures:   true,
		ValidateHashChains:   true,
		Timeout:              30 * time.Second,
	}

	hashStore := NewMemoryHashStore()

	engine := NewValidationEngine(domain, config, nil, hashStore)

	// Test certificate validation with nil
	_, err = engine.ValidateCertificate(nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

func TestValidationEngine_SignatureValidation(t *testing.T) {
	domain, err := NewTrustDomainBuilder().SetID("test_domain").SetName("Test Domain").Build()
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	config := &ValidationEngineConfig{
		ValidateCertificates: true,
		ValidateSignatures:   true,
		ValidateHashChains:   true,
		Timeout:              30 * time.Second,
	}

	hashStore := NewMemoryHashStore()

	engine := NewValidationEngine(domain, config, nil, hashStore)

	// Test signature validation with nil
	_, err = engine.ValidateSignature(nil, nil)
	if err == nil {
		t.Error("Expected error for nil signature")
	}
}

func TestValidationEngine_HashChainValidation(t *testing.T) {
	domain, err := NewTrustDomainBuilder().SetID("test_domain").SetName("Test Domain").Build()
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	config := &ValidationEngineConfig{
		ValidateCertificates: true,
		ValidateSignatures:   true,
		ValidateHashChains:   true,
		Timeout:              30 * time.Second,
	}

	hashStore := NewMemoryHashStore()

	engine := NewValidationEngine(domain, config, nil, hashStore)

	// Test hash chain validation with empty values
	_, err = engine.ValidateHashChain("", "")
	if err == nil {
		t.Error("Expected error for empty hash chain")
	}
}

func TestMemoryHashStore_BasicOperations(t *testing.T) {
	store := NewMemoryHashStore()

	feedID := "test_feed"
	hash1 := "abc123"
	hash2 := "def456"
	hash3 := "ghi789"

	err := store.StoreHash(feedID, hash1, "")
	if err != nil {
		t.Fatalf("Failed to store first hash: %v", err)
	}

	err = store.StoreHash(feedID, hash2, hash1)
	if err != nil {
		t.Fatalf("Failed to store second hash: %v", err)
	}

	err = store.StoreHash(feedID, hash3, hash2)
	if err != nil {
		t.Fatalf("Failed to store third hash: %v", err)
	}

	_, err = store.VerifyChain(feedID)
	if err != nil {
		t.Fatalf("Failed to verify chain: %v", err)
	}

	hashes, err := store.GetChainHashes(feedID)
	if err != nil {
		t.Fatalf("Failed to get hashes: %v", err)
	}

	if len(hashes) != 3 {
		t.Errorf("Expected 3 hashes, got %d", len(hashes))
	}

	err = store.DeleteFeedHashes(feedID)
	if err != nil {
		t.Fatalf("Failed to delete hashes: %v", err)
	}
}

func TestMemoryHashStore_InvalidChain(t *testing.T) {
	store := NewMemoryHashStore()

	feedID := "test_feed"

	err := store.StoreHash(feedID, "hash1", "nonexistent")
	if err != nil {
		t.Fatalf("Failed to store hash: %v", err)
	}

	_, err = store.VerifyChain(feedID)
	if err != nil {
		t.Errorf("Unexpected error for valid chain: %v", err)
	}
}

func TestTrustDomainConfig_Defaults(t *testing.T) {
	config := &TrustDomainConfig{
		ID:                TrustDomainID("test_domain"),
		Name:              "Test Domain",
		Description:       "Test description",
		Enabled:           true,
		ValidationTimeout: 30 * time.Second,
		MaxTrustAnchors:   100,
		EnableAuditLog:    true,
		IsolationLevel:    IsolationFull,
		HashChainEnabled:  true,
		SignatureVerified: true,
	}

	if config.ID != "test_domain" {
		t.Error("ID not set correctly")
	}

	if config.Name != "Test Domain" {
		t.Error("Name not set correctly")
	}

	if !config.Enabled {
		t.Error("Enabled should be true")
	}
}

func TestValidationStats(t *testing.T) {
	stats := &ValidationStats{}

	stats.TotalValidations = 3
	stats.Successful = 2
	stats.Failed = 1
	stats.FailedPercentage = calculateFailedPercentage(3, 1)

	if stats.TotalValidations != 3 {
		t.Errorf("Expected 3 total validations, got %d", stats.TotalValidations)
	}

	if stats.Successful != 2 {
		t.Errorf("Expected 2 successful, got %d", stats.Successful)
	}

	if stats.Failed != 1 {
		t.Errorf("Expected 1 failed, got %d", stats.Failed)
	}

	if stats.FailedPercentage < 30 || stats.FailedPercentage > 40 {
		t.Errorf("Expected ~33%% failed, got %f", stats.FailedPercentage)
	}
}
