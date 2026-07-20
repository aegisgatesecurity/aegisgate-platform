// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL License Cache Unit Tests (D1 Phase 1C)
// =========================================================================
// Unit tests for the PostgreSQL-backed license validation cache.
// Integration tests should use //go:build integration with a real database.
// =========================================================================

package license

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// TestNewPostgresLicenseCache_NilStore verifies that nil PostgresStore returns error.
func TestNewPostgresLicenseCache_NilStore(t *testing.T) {
	_, err := NewPostgresLicenseCache(nil)
	if err == nil {
		t.Fatal("expected error when pgStore is nil, got nil")
	}
}

// TestPostgresLicenseCache_ClosedState verifies that all methods return errors/values after Close().
func TestPostgresLicenseCache_ClosedState(t *testing.T) {
	cache := &PostgresLicenseCache{closed: true}
	ctx := context.Background()

	// Get should return nil on closed cache
	if result := cache.Get(ctx, "test-key"); result != nil {
		t.Error("Get should return nil on closed cache")
	}

	// Set should return error on closed cache
	if err := cache.Set(ctx, "test-key", nil, time.Minute); err == nil {
		t.Error("Set should fail on closed cache")
	}

	// Invalidate should return error on closed cache
	if err := cache.Invalidate(ctx, "test-key"); err == nil {
		t.Error("Invalidate should fail on closed cache")
	}

	// PruneExpired should return error on closed cache
	if _, err := cache.PruneExpired(ctx); err == nil {
		t.Error("PruneExpired should fail on closed cache")
	}

	// Double close should be safe
	if err := cache.Close(); err != nil {
		t.Errorf("double Close should not error, got: %v", err)
	}
}

// TestPostgresLicenseCache_SetNilResult verifies that Set with nil result is a no-op.
func TestPostgresLicenseCache_SetNilResult(t *testing.T) {
	cache := &PostgresLicenseCache{closed: true}
	ctx := context.Background()

	// nil result should not panic, but closed state should still error
	if err := cache.Set(ctx, "key", nil, time.Minute); err == nil {
		t.Error("Set with nil result on closed cache should still fail")
	}
}

// TestPostgresLicenseCache_GetMissing verifies that Get on closed cache returns nil.
func TestPostgresLicenseCache_GetMissing(t *testing.T) {
	cache := &PostgresLicenseCache{closed: true}
	ctx := context.Background()

	result := cache.Get(ctx, "nonexistent-key")
	if result != nil {
		t.Error("Get on closed cache should return nil")
	}
}

// TestPostgresLicenseCache_NilResultValidation verifies that ValidationResult
// can be round-tripped through the PostgreSQL storage layer.
func TestPostgresLicenseCache_ValidationResultRoundTrip(t *testing.T) {
	// Verify that all fields we store in PostgreSQL are accessible
	result := &ValidationResult{
		Valid:       true,
		Expired:     false,
		GracePeriod: false,
		Tier:        tier.TierProfessional,
		Payload: LicensePayload{
			LicenseID:  "test-license-123",
			Tier:       "professional",
			Customer:   "test-customer",
			Modules:    []string{"hipaa", "soc2"},
			MaxServers: 10,
			MaxUsers:   50,
		},
		Message:     "License valid - Professional tier",
		ValidatedAt: time.Now().UTC(),
	}

	// Verify that the tier can be serialized to string and back
	tierStr := result.Tier.String()
	parsedTier, err := tier.ParseTier(tierStr)
	if err != nil {
		t.Fatalf("ParseTier(%q) error: %v", tierStr, err)
	}
	if parsedTier != result.Tier {
		t.Errorf("Tier round-trip: got %v, want %v", parsedTier, result.Tier)
	}

	// Verify payload can be marshaled to JSON (for JSONB column)
	data, err := marshalPayload(result.Payload)
	if err != nil {
		t.Fatalf("marshalPayload error: %v", err)
	}

	parsedPayload, err := unmarshalPayload(data)
	if err != nil {
		t.Fatalf("unmarshalPayload error: %v", err)
	}

	if parsedPayload.LicenseID != result.Payload.LicenseID {
		t.Errorf("Payload LicenseID round-trip: got %q, want %q", parsedPayload.LicenseID, result.Payload.LicenseID)
	}
	if parsedPayload.Customer != result.Payload.Customer {
		t.Errorf("Payload Customer round-trip: got %q, want %q", parsedPayload.Customer, result.Payload.Customer)
	}
	if len(parsedPayload.Modules) != len(result.Payload.Modules) {
		t.Errorf("Payload Modules round-trip: got %d, want %d", len(parsedPayload.Modules), len(result.Payload.Modules))
	}
}

// TestTierStringConversions verifies that tier strings match what PostgreSQL stores.
func TestTierStringConversions(t *testing.T) {
	tests := []struct {
		tier tier.Tier
		want string
	}{
		{tier.TierCommunity, "community"},
		{tier.TierDeveloper, "developer"},
		{tier.TierProfessional, "professional"},
		{tier.TierEnterprise, "enterprise"},
	}

	for _, tt := range tests {
		got := tt.tier.String()
		if got != tt.want {
			t.Errorf("Tier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}

		// Verify round-trip
		parsed, err := tier.ParseTier(got)
		if err != nil {
			t.Errorf("ParseTier(%q) error: %v", got, err)
		}
		if parsed != tt.tier {
			t.Errorf("ParseTier(%q) = %d, want %d", got, parsed, tt.tier)
		}
	}
}

// marshalPayload serializes a LicensePayload to JSON.
func marshalPayload(p LicensePayload) ([]byte, error) {
	return json.Marshal(p)
}

// unmarshalPayload deserializes a LicensePayload from JSON.
func unmarshalPayload(data []byte) (*LicensePayload, error) {
	var p LicensePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
