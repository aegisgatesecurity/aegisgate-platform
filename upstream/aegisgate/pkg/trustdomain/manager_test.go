package trustdomain

import (
	"fmt"
	"testing"
	"time"
)

func TestTrustDomainManager_CreateDomain(t *testing.T) {
	domain, err := NewTrustDomainBuilder().SetID("test_domain").SetName("Test Domain").Build()
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	if domain == nil {
		t.Fatal("Domain is nil")
	}

	// Verify domain operations work
	_, err = domain.ValidateCertificate(nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

func TestTrustDomainManager_Validation(t *testing.T) {
	domain, err := NewTrustDomainBuilder().SetID("test_domain").SetName("Test Domain").Build()
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	// Test certificate validation
	_, err = domain.ValidateCertificate(nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}

	// Test signature validation
	valid, err := domain.ValidateSignature(nil, nil)
	if err == nil {
		t.Error("Expected error for nil signature")
	}

	if valid {
		t.Error("Expected invalid result for nil signature")
	}

	// Test hash chain validation
	valid, err = domain.ValidateHashChain("", "")
	if err == nil {
		t.Error("Expected error for empty hash chain")
	}

	if valid {
		t.Error("Expected invalid result for empty hash chain")
	}
}

func TestTrustDomainManager_Lifecycle(t *testing.T) {
	domain, err := NewTrustDomainBuilder().SetID("test_domain").SetName("Test Domain").Build()
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	// Disable domain
	err = domain.Disable()
	if err != nil {
		t.Fatalf("Failed to disable domain: %v", err)
	}

	// Enable domain
	err = domain.Enable()
	if err != nil {
		t.Fatalf("Failed to enable domain: %v", err)
	}

	// Destroy domain
	err = domain.Destroy()
	if err != nil {
		t.Fatalf("Failed to destroy domain: %v", err)
	}
}

func TestMemoryHashStore(t *testing.T) {
	store := NewMemoryHashStore()

	feedID := "test_feed"
	hash1 := "abc123"
	hash2 := "def456"
	hash3 := "ghi789"

	// Store hashes
	err := store.StoreHash(feedID, hash1, "")
	if err != nil {
		t.Fatalf("Failed to store hash: %v", err)
	}

	err = store.StoreHash(feedID, hash2, hash1)
	if err != nil {
		t.Fatalf("Failed to store hash: %v", err)
	}

	err = store.StoreHash(feedID, hash3, hash2)
	if err != nil {
		t.Fatalf("Failed to store hash: %v", err)
	}

	// Verify hashes can be retrieved
	hashes, err := store.GetChainHashes(feedID)
	if err != nil {
		t.Fatalf("Failed to get hashes: %v", err)
	}

	if len(hashes) != 3 {
		t.Errorf("Expected 3 hashes, got %d", len(hashes))
	}

	// Delete feed hashes
	err = store.DeleteFeedHashes(feedID)
	if err != nil {
		t.Fatalf("Failed to delete hashes: %v", err)
	}

	// Verify hashes are deleted
	hashes, err = store.GetChainHashes(feedID)
	if err != nil {
		t.Fatalf("Failed to get hashes after delete: %v", err)
	}

	if len(hashes) != 0 {
		t.Error("Expected no hashes after deletion")
	}
}

func TestFeedTrustPolicy_Evaluation(t *testing.T) {
	policy := &FeedTrustPolicy{
		FeedID:         "test_feed",
		ValidationMode: ValidationStrict,
		Parameters: map[string]interface{}{
			"timeout":         30 * time.Second,
			"hash_chain":      true,
			"signature_check": true,
		},
	}

	if policy.FeedID != "test_feed" {
		t.Error("FeedID not set correctly")
	}

	if policy.ValidationMode != ValidationStrict {
		t.Error("ValidationMode not set correctly")
	}
}

func TestValidationEngine_Stats(t *testing.T) {
	domain, err := NewTrustDomainBuilder().SetID("test_domain").SetName("Test Domain").Build()
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	hashStore := NewMemoryHashStore()

	config := &ValidationEngineConfig{
		ValidateCertificates: true,
		ValidateSignatures:   true,
		ValidateHashChains:   true,
		Timeout:              30 * time.Second,
	}

	engine := NewValidationEngine(domain, config, nil, hashStore)

	// Run some validations
	_, _ = engine.ValidateCertificate(nil)
	_, _ = engine.ValidateSignature(nil, nil)
	_, _ = engine.ValidateHashChain("", "")

	// Check stats
	stats := engine.GetStats()

	if stats.TotalValidations != 3 {
		t.Errorf("Expected 3 total validations, got %d", stats.TotalValidations)
	}
}

func TestTrustDomainManager_ConcurrentAccess(t *testing.T) {
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			domain, err := NewTrustDomainBuilder().SetID(TrustDomainID(fmt.Sprintf("domain_%d", id))).SetName(fmt.Sprintf("Domain %d", id)).Build()
			if err != nil {
				t.Errorf("Failed to create domain %d: %v", id, err)
			}

			if domain != nil {
				_ = domain.Destroy()
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMemoryHashStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryHashStore()

	done := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func(id int) {
			feedID := fmt.Sprintf("feed_%d", id%10)
			hash := fmt.Sprintf("hash_%d_%d", id, id)
			err := store.StoreHash(feedID, hash, "previous")
			if err != nil {
				t.Errorf("Failed to store hash %d: %v", id, err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
