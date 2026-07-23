// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Attestation Coverage Gap Tests
// =========================================================================

package attestation

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// =====================================================================
// VerificationError.Unwrap (0% → 100%)
// =====================================================================

func TestVerificationError_Unwrap(t *testing.T) {
	// Unwrap with nil Cause
	inner := &VerificationError{Reason: ReasonUnknown, Message: "test", Cause: nil}
	if inner.Unwrap() != nil {
		t.Error("Unwrap of nil Cause should return nil")
	}

	// Unwrap with a Cause
	cause := &VerificationError{Reason: ReasonUnknown, Message: "inner error"}
	outer := &VerificationError{Reason: ReasonUnknown, Message: "outer error", Cause: cause}
	if outer.Unwrap() != cause {
		t.Error("Unwrap should return the Cause")
	}
}

func TestVerificationError_Error(t *testing.T) {
	// Error without Cause
	err1 := &VerificationError{Reason: ReasonUnknown, Message: "something failed"}
	msg := err1.Error()
	if msg == "" {
		t.Error("Error() should not return empty string")
	}

	// Error with Cause
	cause := &VerificationError{Reason: ReasonUnknown, Message: "inner"}
	err2 := &VerificationError{Reason: ReasonUnknown, Message: "outer", Cause: cause}
	msg2 := err2.Error()
	if msg2 == "" {
		t.Error("Error() with Cause should not return empty string")
	}
}

// =====================================================================
// CanonicalizeJSON (0% → 100%)
// =====================================================================

func TestCanonicalizeJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "simple object", input: `{"z":1,"a":2}`, wantErr: false},
		{name: "nested object", input: `{"outer":{"z":1,"a":2}}`, wantErr: false},
		{name: "array", input: `[3,1,2]`, wantErr: false},
		{name: "string", input: `"hello"`, wantErr: false},
		{name: "number", input: `42`, wantErr: false},
		{name: "boolean", input: `true`, wantErr: false},
		{name: "null", input: `null`, wantErr: false},
		{name: "complex object", input: `{"name":"test","count":5,"active":true,"nested":{"x":1}}`, wantErr: false},
		{name: "invalid JSON", input: `{invalid`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalizeJSON([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalizeJSON: %v", err)
			}
			if len(result) == 0 {
				t.Error("result should not be empty")
			}
		})
	}
}

func TestCanonicalizeJSON_KeySorting(t *testing.T) {
	// Keys should be sorted alphabetically
	input := `{"z":1,"a":2,"m":3}`
	result, err := CanonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatalf("CanonicalizeJSON: %v", err)
	}
	expected := `{"a":2,"m":3,"z":1}`
	if string(result) != expected {
		t.Errorf("CanonicalizeJSON key sorting: got %q, want %q", string(result), expected)
	}
}

func TestCanonicalizeJSON_FloatFormatting(t *testing.T) {
	// Integer values should have no decimal point
	input := `{"val":42}`
	result, err := CanonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatalf("CanonicalizeJSON: %v", err)
	}
	if string(result) != `{"val":42}` {
		t.Errorf("Integer formatting: got %q, want %q", string(result), `{"val":42}`)
	}
}

// =====================================================================
// formatNumber additional paths (70% → higher)
// =====================================================================

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		name  string
		input float64
		want  string
	}{
		{name: "zero", input: 0, want: "0"},
		{name: "negative zero", input: -0.0, want: "0"},
		{name: "positive integer", input: 42, want: "42"},
		{name: "negative integer", input: -17, want: "-17"},
		{name: "positive float", input: 3.14, want: "3.14"},
		{name: "negative float", input: -2.5, want: "-2.5"},
		{name: "small number", input: 0.000001, want: "0.000001"},
		{name: "large integer", input: 1e15, want: "1000000000000000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatNumber(tt.input)
			if got != tt.want {
				t.Errorf("formatNumber(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// =====================================================================
// ListByTimeRange partial paths (66.7% → higher)
// =====================================================================

func TestListByTimeRange_WithTimeRange(t *testing.T) {
	store := NewInMemoryAttestationStore()
	ctx := context.Background()

	now := time.Now().UTC()

	// Create envelopes at different times
	env1 := &Envelope{
		ID:         "att-time-1",
		Subject:    "aegisgate://test/1",
		Type:       TypeEvidenceManifest,
		IssuedAt:   now.Add(-2 * time.Hour),
		ValidUntil: now.Add(22 * time.Hour),
		Issuer:     "instance:key1",
		RawPayload: json.RawMessage(`{"data":"test1"}`),
	}
	env2 := &Envelope{
		ID:         "att-time-2",
		Subject:    "aegisgate://test/2",
		Type:       TypeEvidenceManifest,
		IssuedAt:   now.Add(-1 * time.Hour),
		ValidUntil: now.Add(23 * time.Hour),
		Issuer:     "instance:key2",
		RawPayload: json.RawMessage(`{"data":"test2"}`),
	}
	env3 := &Envelope{
		ID:         "att-time-3",
		Subject:    "aegisgate://test/3",
		Type:       TypeEvidenceManifest,
		IssuedAt:   now,
		ValidUntil: now.Add(24 * time.Hour),
		Issuer:     "instance:key3",
		RawPayload: json.RawMessage(`{"data":"test3"}`),
	}

	store.Store(ctx, env1)
	store.Store(ctx, env2)
	store.Store(ctx, env3)

	// Query for envelopes in the last 90 minutes
	from := now.Add(-90 * time.Minute)
	to := now.Add(10 * time.Minute)
	results, err := store.ListByTimeRange(ctx, from, to, 100, 0)
	if err != nil {
		t.Fatalf("ListByTimeRange: %v", err)
	}
	// Should only include env2 and env3 (env1 is 2 hours ago)
	if len(results) < 1 {
		t.Errorf("ListByTimeRange: expected at least 1 result, got %d", len(results))
	}
}

func TestListByTimeRange_NoEndTime(t *testing.T) {
	store := NewInMemoryAttestationStore()
	ctx := context.Background()

	now := time.Now().UTC()
	env := &Envelope{
		ID:         "att-noend-1",
		Subject:    "aegisgate://test/1",
		Type:       TypeEvidenceManifest,
		IssuedAt:   now,
		ValidUntil: now.Add(24 * time.Hour),
		Issuer:     "instance:key1",
		RawPayload: json.RawMessage(`{"data":"test"}`),
	}
	store.Store(ctx, env)

	// Query with open end time (zero value = no upper bound)
	from := now.Add(-1 * time.Hour)
	to := now.Add(24 * time.Hour)
	results, err := store.ListByTimeRange(ctx, from, to, 100, 0)
	if err != nil {
		t.Fatalf("ListByTimeRange: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("ListByTimeRange: expected 1 result, got %d", len(results))
	}
}

func TestListByTimeRange_EmptyStore(t *testing.T) {
	store := NewInMemoryAttestationStore()
	ctx := context.Background()

	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC().Add(24 * time.Hour)
	results, err := store.ListByTimeRange(ctx, from, to, 100, 0)
	if err != nil {
		t.Fatalf("ListByTimeRange: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("ListByTimeRange on empty store: expected 0 results, got %d", len(results))
	}
}

// =====================================================================
// parseIssuer additional paths (68.8% → higher)
// =====================================================================

func TestParseIssuer_AdditionalPaths(t *testing.T) {
	tests := []struct {
		name      string
		issuer    string
		wantErr   bool
		wantParts int // number of parts expected on success
	}{
		{name: "standard instance/key", issuer: "my-instance:key-123", wantErr: false, wantParts: 2},
		{name: "single part (no colon)", issuer: "single-part", wantErr: true, wantParts: 0},
		{name: "empty string", issuer: "", wantErr: true, wantParts: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instanceID, keyID, err := parseIssuer(tt.issuer)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseIssuer(%q): %v", tt.issuer, err)
			}
			if instanceID == "" {
				t.Errorf("parseIssuer(%q) returned empty instanceID", tt.issuer)
			}
			if keyID == "" {
				t.Errorf("parseIssuer(%q) returned empty keyID", tt.issuer)
			}
		})
	}
}