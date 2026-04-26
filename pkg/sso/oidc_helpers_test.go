// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package sso

import (
	"encoding/base64"
	"testing"
)

// =============================================================================
// OIDC Helper Function Tests
// =============================================================================

func TestGetString(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		key  string
		want string
	}{
		{
			name: "string value",
			m:    map[string]interface{}{"name": "John Doe"},
			key:  "name",
			want: "John Doe",
		},
		{
			name: "float value",
			m:    map[string]interface{}{"age": float64(30)},
			key:  "age",
			want: "30",
		},
		{
			name: "key not found",
			m:    map[string]interface{}{"name": "John"},
			key:  "email",
			want: "",
		},
		{
			name: "empty key",
			m:    map[string]interface{}{"name": "John"},
			key:  "",
			want: "",
		},
		{
			name: "nil map",
			m:    nil,
			key:  "name",
			want: "",
		},
		{
			name: "bool value (not a string)",
			m:    map[string]interface{}{"active": true},
			key:  "active",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getString(tt.m, tt.key)
			if got != tt.want {
				t.Errorf("getString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetStringSlice(t *testing.T) {
	tests := []struct {
		name    string
		m       map[string]interface{}
		key     string
		want    []string
		wantNil bool
	}{
		{
			name:    "[]interface{} value",
			m:       map[string]interface{}{"groups": []interface{}{"admin", "users"}},
			key:     "groups",
			want:    []string{"admin", "users"},
			wantNil: false,
		},
		{
			name:    "[]string value",
			m:       map[string]interface{}{"roles": []string{"dev", "qa"}},
			key:     "roles",
			want:    []string{"dev", "qa"},
			wantNil: false,
		},
		{
			name:    "single string value",
			m:       map[string]interface{}{"email": "user@example.com"},
			key:     "email",
			want:    []string{"user@example.com"},
			wantNil: false,
		},
		{
			name:    "key not found",
			m:       map[string]interface{}{"name": "John"},
			key:     "missing",
			want:    nil,
			wantNil: true,
		},
		{
			name:    "empty key",
			m:       map[string]interface{}{"groups": []string{"a"}},
			key:     "",
			want:    nil,
			wantNil: true,
		},
		{
			name:    "nil map",
			m:       nil,
			key:     "name",
			want:    nil,
			wantNil: true,
		},
		{
			name:    "bool value (not a slice)",
			m:       map[string]interface{}{"active": true},
			key:     "active",
			want:    nil,
			wantNil: true,
		},
		{
			name:    "empty interface slice",
			m:       map[string]interface{}{"empty": []interface{}{}},
			key:     "empty",
			want:    []string{},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringSlice(tt.m, tt.key)
			if tt.wantNil {
				if got != nil {
					t.Errorf("getStringSlice() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("getStringSlice() len = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("getStringSlice()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGenerateCodeVerifier(t *testing.T) {
	verifier := generateCodeVerifier()

	// Should be 32 bytes of random data, base64 encoded -> ~43 chars
	if len(verifier) < 40 || len(verifier) > 50 {
		t.Errorf("generateCodeVerifier() length = %d, want ~43", len(verifier))
	}

	// Should be valid base64
	_, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil {
		t.Errorf("generateCodeVerifier() should produce valid base64: %v", err)
	}

	// Should be unique
	verifier2 := generateCodeVerifier()
	if verifier == verifier2 {
		t.Error("generateCodeVerifier() should generate unique values")
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	tests := []struct {
		name     string
		verifier string
		method   string
	}{
		{
			name:     "S256 method",
			verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			method:   "S256",
		},
		{
			name:     "plain method",
			verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			method:   "plain",
		},
		{
			name:     "empty method (defaults to S256)",
			verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			method:   "",
		},
		{
			name:     "unknown method (defaults to S256)",
			verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			method:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := generateCodeChallenge(tt.verifier, tt.method)
			if challenge == "" {
				t.Error("generateCodeChallenge() returned empty string")
			}
			// S256 should produce a hash
			if tt.method == "S256" || tt.method == "" || tt.method == "unknown" {
				if len(challenge) < 40 {
					t.Errorf("generateCodeChallenge(S256) length = %d, want ~43", len(challenge))
				}
			}
			// plain should return the verifier unchanged
			if tt.method == "plain" && challenge != tt.verifier {
				t.Errorf("generateCodeChallenge(plain) = %q, want %q", challenge, tt.verifier)
			}
		})
	}
}

// Test that S256 produces consistent output
func TestGenerateCodeChallengeS256Consistency(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// Generate two challenges - they should be identical
	challenge1 := generateCodeChallenge(verifier, "S256")
	challenge2 := generateCodeChallenge(verifier, "S256")

	if challenge1 != challenge2 {
		t.Error("S256 challenge should be deterministic")
	}

	// Verify it's valid base64
	_, err := base64.RawURLEncoding.DecodeString(challenge1)
	if err != nil {
		t.Errorf("S256 challenge should be valid base64: %v", err)
	}
}
