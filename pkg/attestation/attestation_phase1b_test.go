// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"bytes"
	"context"
	"math"
	"testing"
	"time"
)

// TestPhase1bIsPrivateOrReservedHost exercises all branches of the SSRF guard.
func TestPhase1bIsPrivateOrReservedHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"169.254.169.254", true},  // AWS metadata
		{"10.0.0.1", true},         // private class A
		{"172.16.0.1", true},       // private class B
		{"192.168.1.1", true},      // private class C
		{"fd00::1", true},          // IPv6 ULA
		{"0.0.0.0", true},          // all zeros
		{"127.0.0.2", true},        // non-loopback 127.x
		{"127.0.0.1", false},       // loopback (allowed)
		{"example.com", false},     // public
		{"8.8.8.8", false},         // public
		{"192.168.1.1:8080", true}, // with port
		{"example.com:443", false}, // public with port
	}
	for _, tt := range tests {
		got := isPrivateOrReservedHost(tt.host)
		if got != tt.want {
			t.Errorf("isPrivateOrReservedHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

// TestPhase1bFormatNumber exercises all branches of the number formatter.
func TestPhase1bFormatNumber(t *testing.T) {
	tests := []struct {
		name string
		f    float64
		want string
	}{
		{"integer", 42.0, "42"},
		{"negative_integer", -17.0, "-17"},
		{"zero", 0.0, "0"},
		{"negative_zero", -0.0, "0"},
		{"normal_float", 3.14, "3.14"},
		{"small_float", 0.0001, "0.0001"},
		{"large_float", 1e25, "1e+25"},
		{"nan", math.NaN(), "null"},
		{"pos_inf", math.Inf(1), "null"},
		{"neg_inf", math.Inf(-1), "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatNumber(tt.f)
			if got != tt.want {
				t.Errorf("formatNumber(%v) = %q, want %q", tt.f, got, tt.want)
			}
		})
	}
}

// TestPhase1bCanonicalMarshal exercises canonical JSON marshaling with
// different data types to cover more writeCanonical branches.
func TestPhase1bCanonicalMarshal_Types(t *testing.T) {
	tests := []struct {
		name string
		v    interface{}
	}{
		{"nil", nil},
		{"bool_true", true},
		{"bool_false", false},
		{"string", "hello"},
		{"integer", 42},
		{"float", 3.14},
		{"array", []interface{}{1, "two", true}},
		{"nested_object", map[string]interface{}{
			"b": 2,
			"a": 1,
			"c": []interface{}{3, 2, 1},
		}},
		{"empty_object", map[string]interface{}{}},
		{"empty_array", []interface{}{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := canonicalMarshal(tt.v)
			if err != nil {
				t.Errorf("canonicalMarshal(%v) error: %v", tt.v, err)
			}
		})
	}
}

// TestPhase1bCanonicalizeJSON exercises the public CanonicalizeJSON wrapper.
func TestPhase1bCanonicalizeJSON(t *testing.T) {
	input := []byte(`{"b":2,"a":1}`)
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("CanonicalizeJSON error: %v", err)
	}
	// JCS should sort keys: {"a":1,"b":2}
	if string(result) != `{"a":1,"b":2}` {
		t.Errorf("expected {\"a\":1,\"b\":2}, got %s", string(result))
	}
}

// TestPhase1bCanonicalizeJSON_Invalid exercises the error path.
func TestPhase1bCanonicalizeJSON_Invalid(t *testing.T) {
	_, err := CanonicalizeJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestPhase1bWriteCanonical_NonASCIIString exercises the non-ASCII error path.
func TestPhase1bWriteCanonical_NonASCIIString(t *testing.T) {
	var buf bytes.Buffer
	err := writeCanonical(&buf, "héllo")
	if err == nil {
		t.Fatal("expected error for non-ASCII string")
	}
}

// TestPhase1bWriteCanonical_NonASCIIKey exercises the non-ASCII key error path.
func TestPhase1bWriteCanonical_NonASCIIKey(t *testing.T) {
	var buf bytes.Buffer
	err := writeCanonical(&buf, map[string]interface{}{
		"héllo": 1,
	})
	if err == nil {
		t.Fatal("expected error for non-ASCII key")
	}
}

// TestPhase1bWriteCanonical_NonFiniteFloat exercises the NaN/Inf error path.
func TestPhase1bWriteCanonical_NonFiniteFloat(t *testing.T) {
	var buf bytes.Buffer
	err := writeCanonical(&buf, math.NaN())
	if err == nil {
		t.Fatal("expected error for NaN")
	}
	err = writeCanonical(&buf, math.Inf(1))
	if err == nil {
		t.Fatal("expected error for Inf")
	}
}

// TestPhase1bWriteCanonical_UnsupportedType exercises the default error path.
func TestPhase1bWriteCanonical_UnsupportedType(t *testing.T) {
	var buf bytes.Buffer
	err := writeCanonical(&buf, complex(1, 2))
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

// TestPhase1bWriteCanonical_NestedArray exercises nested arrays in maps.
func TestPhase1bWriteCanonical_NestedArray(t *testing.T) {
	var buf bytes.Buffer
	v := map[string]interface{}{
		"items": []interface{}{float64(1), float64(2), float64(3)},
		"name":  "test",
	}
	err := writeCanonical(&buf, v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPhase1bVerificationReason_String_Unknown exercises the default
// case in the String method (reason_N format).
func TestPhase1bVerificationReason_String_Unknown(t *testing.T) {
	r := VerificationReason(999)
	s := r.String()
	if s != "reason_999" {
		t.Errorf("expected 'reason_999', got %q", s)
	}
}

// TestPhase1bVerificationReason_String_AllReasons exercises all reasons.
func TestPhase1bVerificationReason_String_AllReasons(t *testing.T) {
	reasons := []VerificationReason{
		ReasonNotYetValid,
		ReasonPublicKeyFetch,
		ReasonAlgorithmUnsupported,
	}
	for _, r := range reasons {
		s := r.String()
		if s == "" {
			t.Errorf("expected non-empty string for reason %d", r)
		}
	}
}

// TestPhase1bFetchPublicKey_InvalidInstanceID exercises the instance ID
// validation paths in fetchPublicKey.
func TestPhase1bFetchPublicKey_InvalidInstanceID(t *testing.T) {
	ctx := context.Background()
	invalidIDs := []string{
		"",
		"host/with/slash",
		"host\\with\\backslash",
		"host?with=query",
		"host#with fragment",
		"../traversal",
	}
	for _, id := range invalidIDs {
		_, err := fetchPublicKey(ctx, id, "key-1")
		if err == nil {
			t.Errorf("expected error for invalid instanceID %q", id)
		}
	}
}

// TestPhase1bFetchPublicKey_PrivateHost exercises the SSRF rejection path.
func TestPhase1bFetchPublicKey_PrivateHost(t *testing.T) {
	ctx := context.Background()
	privateHosts := []string{
		"10.0.0.1",
		"192.168.1.1",
		"169.254.169.254",
	}
	for _, host := range privateHosts {
		_, err := fetchPublicKey(ctx, host, "key-1")
		if err == nil {
			t.Errorf("expected error for private host %q", host)
		}
	}
}

// TestPhase1bSign_NilKeyring exercises the nil keyring error path.
func TestPhase1bSign_NilKeyring(t *testing.T) {
	_, err := Sign([]byte("payload"), "test", TypeEvidenceManifest, "issuer", nil, time.Hour)
	if err == nil {
		t.Fatal("expected error for nil keyring")
	}
}

// TestPhase1bSign_EmptyPayload exercises the empty payload error path.
func TestPhase1bSign_EmptyPayload(t *testing.T) {
	_, err := Sign(nil, "test", TypeEvidenceManifest, "issuer", nil, time.Hour)
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

// TestPhase1bParseSubject exercises the subject parser with various inputs.
func TestPhase1bParseSubject(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		wantErr bool
	}{
		{"empty", "", true},
		{"wrong_scheme", "http://kind/id", true},
		{"missing_kind", "aegisgate:///id", true},
		{"missing_id", "aegisgate://kind/", true},
		{"valid", "aegisgate://agent/agent-1", false},
		{"valid_with_slashes", "aegisgate://tenant/org/sub/id", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseSubject(tt.subject)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestPhase1bPostgresStore_NilEnvelope exercises the nil envelope guard.
func TestPhase1bPostgresStore_NilEnvelope(t *testing.T) {
	s := NewPostgresAttestationStore(nil)
	err := s.Store(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil envelope")
	}
}

// TestPhase1bPostgresStore_GetEmptyID exercises the empty ID guard.
func TestPhase1bPostgresStore_GetEmptyID(t *testing.T) {
	s := NewPostgresAttestationStore(nil)
	_, err := s.Get(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

// TestPhase1bVerificationReason_String exercises the String method.
func TestPhase1bVerificationReason_String(t *testing.T) {
	tests := []struct {
		r    VerificationReason
		want string
	}{
		{ReasonUnknown, "unknown"},
		{ReasonMalformed, "malformed"},
		{ReasonUnknownType, "unknown_type"},
		{ReasonInvalidSubject, "invalid_subject"},
		{ReasonSignatureInvalid, "signature_invalid"},
	}
	for _, tt := range tests {
		s := tt.r.String()
		if s != tt.want {
			t.Errorf("String() = %q, want %q", s, tt.want)
		}
	}
}
