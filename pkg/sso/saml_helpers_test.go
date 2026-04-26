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
// SAML Helper Function Tests
// =============================================================================

func TestGenerateRequestID(t *testing.T) {
	id := generateRequestID()

	// Should start with underscore
	if len(id) == 0 || id[0] != '_' {
		t.Errorf("generateRequestID() should start with '_', got %q", id)
	}

	// Should be unique
	id2 := generateRequestID()
	if id == id2 {
		t.Error("generateRequestID() should generate unique IDs")
	}

	// Should be reasonable length (16 bytes -> ~32 hex chars + underscore)
	if len(id) < 30 || len(id) > 40 {
		t.Errorf("generateRequestID() length unexpected: %d", len(id))
	}
}

func TestGenerateSessionID(t *testing.T) {
	id := generateSessionID()

	// Should be base64 encoded (32 bytes -> ~43 chars)
	if len(id) < 40 || len(id) > 50 {
		t.Errorf("generateSessionID() length unexpected: %d", len(id))
	}

	// Should be unique
	id2 := generateSessionID()
	if id == id2 {
		t.Error("generateSessionID() should generate unique IDs")
	}

	// Should be valid base64
	_, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Errorf("generateSessionID() should produce valid base64: %v", err)
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantZero bool
	}{
		{
			name:     "valid RFC3339 time",
			input:    "2024-01-15T10:30:00Z",
			wantZero: false,
		},
		{
			name:     "valid RFC3339 with timezone",
			input:    "2024-01-15T10:30:00-05:00",
			wantZero: false,
		},
		{
			name:     "invalid format",
			input:    "2024-01-15",
			wantZero: true,
		},
		{
			name:     "empty string",
			input:    "",
			wantZero: true,
		},
		{
			name:     "garbage input",
			input:    "not a time",
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTime(tt.input)
			if tt.wantZero {
				if !got.IsZero() {
					t.Errorf("parseTime(%q) = %v, want zero", tt.input, got)
				}
			} else {
				if got.IsZero() {
					t.Errorf("parseTime(%q) = zero, want non-zero", tt.input)
				}
			}
		})
	}
}

func TestExtractSLOLocations(t *testing.T) {
	tests := []struct {
		name     string
		services []SingleLogoutService
		wantLen  int
		wantErr  bool
	}{
		{
			name:     "empty services",
			services: []SingleLogoutService{},
			wantLen:  0,
			wantErr:  false,
		},
		{
			name: "single service",
			services: []SingleLogoutService{
				{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.example.com/slo"},
			},
			wantLen: 1,
			wantErr: false,
		},
		{
			name: "multiple services",
			services: []SingleLogoutService{
				{Binding: "redirect", Location: "https://idp1.example.com/slo"},
				{Binding: "post", Location: "https://idp2.example.com/slo"},
			},
			wantLen: 2,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSLOLocations(tt.services)
			if len(got) != tt.wantLen {
				t.Errorf("extractSLOLocations() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestExtractLocations(t *testing.T) {
	tests := []struct {
		name     string
		services []SingleSignOnService
		wantLen  int
	}{
		{
			name:     "empty services",
			services: []SingleSignOnService{},
			wantLen:  0,
		},
		{
			name: "single service",
			services: []SingleSignOnService{
				{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.example.com/sso"},
			},
			wantLen: 1,
		},
		{
			name: "multiple services",
			services: []SingleSignOnService{
				{Binding: "redirect", Location: "https://idp1.example.com/sso"},
				{Binding: "post", Location: "https://idp2.example.com/sso"},
				{Binding: "soap", Location: "https://idp3.example.com/sso"},
			},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLocations(tt.services)
			if len(got) != tt.wantLen {
				t.Errorf("extractLocations() len = %d, want %d", len(got), tt.wantLen)
			}
			// Verify locations match
			for i, svc := range tt.services {
				if got[i] != svc.Location {
					t.Errorf("extractLocations()[%d] = %q, want %q", i, got[i], svc.Location)
				}
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	// Valid 2048-bit test certificate (base64 of DER-encoded X.509 certificate)
	validCertB64 := "MIICnzCCAYegAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQKEwhUZXN0IE9yZzAeFw0yNjA0MjYwMDQxMjdaFw0yNjA0MjcwMDQxMjdaMBMxETAPBgNVBAoTCFRlc3QgT3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqhL5j+wycWkL0NANcI6bxpbXqD8W36M2cRNJVcEZJaq1tzm64T450Kj3LnCrlRtb/yYULOPC2qshhAJVxT36OfJJnG2ztYd8pZ1wG6dke6gzOR6JM9CpPOIftY+2vbkYEmxnp0rcfZrVzrIkkpKX39y15f4F3L097CWUtyXiG7imUAPihqIcG7Z5VHnYNQYL5jMQD2415s0k6MBjfrNAPvFVkJn3tPUMmzUgRJ+xWgGIUE4b/XbOXOqyFSpL5hZi5VnLny7dg5dpVzOihGBDCTpJW2hdALDYmUDNhL3V5WZkfE+pfcAfBrleB5/I3e4GNdVfSFaCWq4UBH4JSm0MuQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBD/yF7iNoQUy7dIzhaF9d/VnqQcldUWrqIfDs0FII1VYNIsIMGBoBgpI3DEuoF1NJWJxFu6ywE9+D6UvOU5vbI9jRYp5PO1rveoygi8R1IVbMph7OPeW8tAXHMBxETWDdqSFtaFw7aexBGBJPzL1gqPxynKCDXjWENr6N5GXC/aelMNY32pC1/Z23URuvVhO2umwJb+zgghKTTDnyw4eKPUEw8z5T/VNHPq09+p/HbQFdyksLiBZQcwpCJhs701WZ1FNlJIUwmk3i6TI+S98vF50F9VpmTzKe3+xUfwlfDNKbxZCWdHnsSjt6BK253CsW2fBPs51VHjWkvAwDL4gQ4"

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid certificate DER bytes",
			input:   validCertB64,
			wantErr: false,
		},
		{
			name:    "valid certificate with PEM headers",
			input:   "-----BEGIN CERTIFICATE-----\n" + validCertB64 + "\n-----END CERTIFICATE-----",
			wantErr: false,
		},
		{
			name:    "valid certificate with newlines stripped",
			input:   validCertB64 + "\n\n",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			input:   "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "invalid certificate data (valid b64 but not a cert)",
			input:   "dW5kZWZpbmVk",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseCertificate(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("parseCertificate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("parseCertificate() unexpected error: %v", err)
				}
				if cert == nil {
					t.Error("parseCertificate() returned nil certificate")
				}
			}
		})
	}
}

func TestExtractStringSlice(t *testing.T) {
	tests := []struct {
		name       string
		attributes map[string]interface{}
		key        string
		want       []string
	}{
		{
			name:       "nil attributes",
			attributes: nil,
			key:        "groups",
			want:       nil,
		},
		{
			name:       "key not in map",
			attributes: map[string]interface{}{"name": "John"},
			key:        "groups",
			want:       nil,
		},
		{
			name:       "empty key",
			attributes: map[string]interface{}{"groups": []string{"admin", "users"}},
			key:        "",
			want:       nil,
		},
		{
			name: "single string value",
			attributes: map[string]interface{}{
				"email": "user@example.com",
			},
			key:  "email",
			want: []string{"user@example.com"},
		},
		{
			name: "string slice value",
			attributes: map[string]interface{}{
				"groups": []string{"admin", "users", "developers"},
			},
			key:  "groups",
			want: []string{"admin", "users", "developers"},
		},
		{
			name: "interface slice value",
			attributes: map[string]interface{}{
				"groups": []interface{}{"admin", "users"},
			},
			key:  "groups",
			want: []string{"admin", "users"},
		},
		{
			name: "mixed interface slice",
			attributes: map[string]interface{}{
				"values": []interface{}{"a", "b", "c"},
			},
			key:  "values",
			want: []string{"a", "b", "c"},
		},
		{
			name: "interface slice with non-strings",
			attributes: map[string]interface{}{
				"numbers": []interface{}{"one", "two"},
			},
			key:  "numbers",
			want: []string{"one", "two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStringSlice(tt.attributes, tt.key)
			if tt.want == nil {
				if got != nil {
					t.Errorf("extractStringSlice() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("extractStringSlice() len = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractStringSlice()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
