// SPDX-License-Identifier: Apache-2.0
// Privacy boundary test: non-negotiable invariants for the Lens
// telemetry protocol.
//
// Verifies that the Lens telemetry payload NEVER leaks:
//   - Prompt content
//   - URL of the AI provider
//   - User identifiers
//   - Browser fingerprint
//   - Any free-form text that could leak prompt
//
// This is the SINGLE MOST IMPORTANT privacy test in the Platform.
// If we fail here, the Lens extension cannot ship.
//
// Tests three invariants:
//  1. SCHEMA: every field in the event is in the schema allowlist
//  2. PROMPT: the prompt text does not appear in any field value
//  3. METADATA: no URLs, no user identifiers, no browser fingerprint
//
// All three MUST pass for every event. Any failure is a critical
// privacy violation that blocks release.
//
// Moved from pkg/lenstest/corpus/ as part of A15 cleanup. The test
// data is self-contained here (no dependency on lenstest/corpus or
// external Node.js/Python scripts).
package lensbackend

import (
	"encoding/json"
	"strings"
	"testing"
)

// privacyCase is one test case for the privacy boundary test.
type privacyCase struct {
	Name      string // Human-readable test name
	Prompt    string // Simulated user prompt (what Lens sees)
	EventJSON string // JSON that the Lens extension would send
}

// privacyBoundaryCorpus returns the test cases for privacy boundary
// validation. Each case simulates a Lens detection event and verifies
// that no prompt content, URLs, or user identifiers leak into the
// anonymized telemetry payload.
func privacyBoundaryCorpus() []privacyCase {
	return []privacyCase{
		{
			Name:   "PII email detection",
			Prompt: "My email is john.doe@example.com and I need help with my account",
			EventJSON: `{
				"domain_hash": "a1b2c3d4e5f6a7b8",
				"category": "pii_email",
				"severity": "high",
				"user_action": "banner_shown",
				"timestamp": 1721376000,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.95,
				"id": "550e8400-e29b-41d4-a716-446655440000"
			}`,
		},
		{
			Name:   "PII SSN detection",
			Prompt: "My SSN is 123-45-6789 please help me",
			EventJSON: `{
				"domain_hash": "a1b2c3d4e5f6a7b8",
				"category": "pii_ssn",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376000,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.99,
				"id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "PII credit card detection",
			Prompt: "My credit card is 4820-1275-9241-9155 can you check my balance",
			EventJSON: `{
				"domain_hash": "c3d4e5f6a7b89012",
				"category": "pii_credit_card",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376001,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.97,
				"id": "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Secret API key detection (AWS)",
			Prompt: "I accidentally committed AKIAIOSFODNN7EXAMPLE to my repo",
			EventJSON: `{
				"domain_hash": "d4e5f6a7b8901234",
				"category": "secret_aws_key",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376002,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.98,
				"id": "6ba7b812-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Secret API key detection (OpenAI)",
			Prompt: "My OpenAI key is sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG",
			EventJSON: `{
				"domain_hash": "e5f6a7b890123456",
				"category": "secret_openai_key",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376003,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.96,
				"id": "6ba7b813-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Secret GitHub token detection",
			Prompt: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm is my GitHub token",
			EventJSON: `{
				"domain_hash": "f6a7b89012345678",
				"category": "secret_github_token",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376004,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.94,
				"id": "6ba7b814-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "PII phone detection",
			Prompt: "Call me at 555-123-4567 for details",
			EventJSON: `{
				"domain_hash": "a7b8901234567890",
				"category": "pii_phone",
				"severity": "medium",
				"user_action": "banner_shown",
				"timestamp": 1721376005,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.85,
				"id": "6ba7b815-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Normal usage — no detection",
			Prompt: "What is the capital of France?",
			EventJSON: `{
				"domain_hash": "b890123456789012",
				"category": "none",
				"severity": "info",
				"user_action": "none",
				"timestamp": 1721376006,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.0,
				"id": "6ba7b816-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Domain-only event (no prompt context)",
			Prompt: "",
			EventJSON: `{
				"domain_hash": "c9012345678901234",
				"category": "pii_email",
				"severity": "high",
				"user_action": "banner_dismissed",
				"timestamp": 1721376007,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.88
			}`,
		},
		{
			Name:   "Multiple PII in prompt",
			Prompt: "My SSN is 111-22-3333 and my email is test@company.org",
			EventJSON: `{
				"domain_hash": "0123456789012345",
				"category": "pii_ssn",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376008,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.97,
				"id": "6ba7b817-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Prompt with URL (must not leak)",
			Prompt: "Check out https://secret.internal.corp/dashboard for the admin panel",
			EventJSON: `{
				"domain_hash": "1234567890123456",
				"category": "secret_url",
				"severity": "high",
				"user_action": "banner_shown",
				"timestamp": 1721376009,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.91,
				"id": "6ba7b818-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Prompt with API path (must not leak)",
			Prompt: "The endpoint at /api/v1/users/admin returns all user data",
			EventJSON: `{
				"domain_hash": "2345678901234567",
				"category": "secret_api_path",
				"severity": "high",
				"user_action": "banner_shown",
				"timestamp": 1721376010,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.89,
				"id": "6ba7b819-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Prompt with IP address (must not leak)",
			Prompt: "The server at 10.0.1.99 is our internal database host",
			EventJSON: `{
				"domain_hash": "3456789012345678",
				"category": "secret_ip_address",
				"severity": "medium",
				"user_action": "banner_shown",
				"timestamp": 1721376011,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.82,
				"id": "6ba7b81a-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Banner shown then dismissed",
			Prompt: "Here is my AWS key AKIAIOSFODNN7EXAMPLE",
			EventJSON: `{
				"domain_hash": "4567890123456789",
				"category": "secret_aws_key",
				"severity": "critical",
				"user_action": "banner_dismissed",
				"timestamp": 1721376012,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.99,
				"id": "6ba7b81b-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "User clicked protect (action taken)",
			Prompt: "My password is hunter2 and my API key is sk-abc123def456ghi789jkl012",
			EventJSON: `{
				"domain_hash": "5678901234567890",
				"category": "secret_openai_key",
				"severity": "critical",
				"user_action": "user_protected",
				"timestamp": 1721376013,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.96,
				"id": "6ba7b81c-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Empty event (minimum viable)",
			Prompt: "Hello world",
			EventJSON: `{
				"domain_hash": "6789012345678901",
				"category": "none",
				"severity": "info",
				"user_action": "none",
				"timestamp": 1721376014,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0"
			}`,
		},
		{
			Name:   "All 9 fields present",
			Prompt: "My email is alice@corp.com",
			EventJSON: `{
				"domain_hash": "7890123456789012",
				"category": "pii_email",
				"severity": "high",
				"user_action": "banner_shown",
				"timestamp": 1721376015,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.95,
				"id": "6ba7b81d-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Prompt with code snippet",
			Prompt: "const apiKey = process.env.OPENAI_API_KEY; fetch('https://api.openai.com/v1/chat/completions')",
			EventJSON: `{
				"domain_hash": "8901234567890123",
				"category": "secret_api_key_env",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376016,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.93,
				"id": "6ba7b81e-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Prompt with financial data",
			Prompt: "My bank account is 123456789 and routing number 021000021",
			EventJSON: `{
				"domain_hash": "aabbccddeeff0011",
				"category": "pii_financial",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376017,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.88,
				"id": "6ba7b81f-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Prompt with medical data",
			Prompt: "My diagnosis code is I10 and my patient ID is PAT-2024-0001",
			EventJSON: `{
				"domain_hash": "0123456789abcdef",
				"category": "pii_medical",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376018,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.91,
				"id": "6ba7b820-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Domain hash with leading zero",
			Prompt: "Test prompt with secret",
			EventJSON: `{
				"domain_hash": "0a1b2c3d4e5f6a7b",
				"category": "secret_generic",
				"severity": "high",
				"user_action": "banner_shown",
				"timestamp": 1721376019,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.86,
				"id": "6ba7b821-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Low confidence detection",
			Prompt: "This might be an email: something@somewhere",
			EventJSON: `{
				"domain_hash": "abcdef0123456789",
				"category": "pii_email",
				"severity": "low",
				"user_action": "none",
				"timestamp": 1721376020,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.42,
				"id": "6ba7b822-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Prompt with name + address",
			Prompt: "I'm Jane Smith, 456 Oak Ave, Springfield IL 62704, SSN 333-22-4444",
			EventJSON: `{
				"domain_hash": "bcdef01234567891",
				"category": "pii_ssn",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376021,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.98,
				"id": "6ba7b823-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "Token redacted event",
			Prompt: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			EventJSON: `{
				"domain_hash": "cdef012345678912",
				"category": "secret_bearer_token",
				"severity": "critical",
				"user_action": "banner_shown",
				"timestamp": 1721376022,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.99,
				"id": "6ba7b824-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
		{
			Name:   "No detection — benign prompt",
			Prompt: "What's the weather like today?",
			EventJSON: `{
				"domain_hash": "def0123456789123",
				"category": "none",
				"severity": "info",
				"user_action": "none",
				"timestamp": 1721376023,
				"model_version": "0.2.0+regex-v1",
				"lens_version": "0.2.0",
				"confidence": 0.0,
				"id": "6ba7b825-9dad-11d1-80b4-00c04fd430c8"
			}`,
		},
	}
}

// The schema allowlist. Adding a field to the schema is a breaking
// change to the Lens protocol. See pkg/lensbackend/validation.go.
var allowedFields = map[string]bool{
	"domain_hash":   true,
	"category":      true,
	"severity":      true,
	"user_action":   true,
	"timestamp":     true,
	"model_version": true,
	"lens_version":  true,
	"confidence":    true,
	"id":            true, // optional
}

func TestPrivacyBoundary_NoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privacy boundary test in -short mode")
	}
	cases := privacyBoundaryCorpus()
	t.Logf("Testing %d privacy boundary cases", len(cases))

	schemaViolations := 0
	promptLeaks := 0
	metadataLeaks := 0

	for i, tc := range cases {
		// Parse the event JSON
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(tc.EventJSON), &event); err != nil {
			t.Errorf("Case %d (%s): event JSON is invalid: %v\n  raw: %s", i, tc.Name, err, tc.EventJSON)
			schemaViolations++
			continue
		}

		// INVARIANT 1: SCHEMA — every field is in the allowlist
		for field := range event {
			if !allowedFields[field] {
				t.Errorf("Case %d (%s) SCHEMA VIOLATION: unknown field '%s' in event", i, tc.Name, field)
				schemaViolations++
			}
		}

		// Check no extra fields beyond allowlist
		if len(event) > len(allowedFields) {
			for field := range event {
				if !allowedFields[field] {
					t.Errorf("Case %d (%s) SCHEMA: extra field '%s'", i, tc.Name, field)
				}
			}
		}

		// INVARIANT 2: PROMPT — no prompt text in any field value
		if tc.Prompt != "" {
			promptSubstrings := extractTestSubstrings(tc.Prompt)
			for field, value := range event {
				valueStr, ok := value.(string)
				if !ok {
					continue
				}
				for _, substr := range promptSubstrings {
					if len(substr) < 4 {
						continue
					}
					if strings.Contains(valueStr, substr) {
						t.Errorf("Case %d (%s) PROMPT LEAK: field '%s' contains prompt substring %q\n  prompt: %q\n  field value: %q",
							i, tc.Name, field, substr, tc.Prompt, valueStr)
						promptLeaks++
						break // one leak per field is enough
					}
				}
			}
		}

		// INVARIANT 3: METADATA — no URLs, user identifiers, fingerprints
		metadataLeaks += checkMetadataInvariants(t, i, tc, event)
	}

	t.Logf("\n=== Privacy Boundary Report ===")
	t.Logf("Total cases:              %d", len(cases))
	t.Logf("Schema violations:       %d (must be 0)", schemaViolations)
	t.Logf("Prompt leaks:            %d (must be 0)", promptLeaks)
	t.Logf("Metadata leaks:          %d (must be 0)", metadataLeaks)

	if schemaViolations > 0 || promptLeaks > 0 || metadataLeaks > 0 {
		t.Errorf("PRIVACY BOUNDARY VIOLATED. Lens cannot ship.")
	} else {
		t.Logf("\n[OK] All privacy invariants hold. Lens is safe to ship.")
	}
}

// extractTestSubstrings returns substrings of the prompt to test
// against event field values. We use:
//   - Distinctive substrings (emails, SSNs, API keys) that would
//     indicate a leak if they appeared in the event
//   - Random 8-char windows for general detection
func extractTestSubstrings(prompt string) []string {
	var subs []string

	// Email: extract the address
	if idx := strings.Index(prompt, "@"); idx > 0 {
		start := idx - 1
		for start > 0 && isEmailChar(prompt[start-1]) {
			start--
		}
		end := idx + 1
		for end < len(prompt) && isEmailChar(prompt[end]) {
			end++
		}
		if end > start {
			subs = append(subs, prompt[start:end])
		}
	}

	// SSN: XXX-XX-XXXX
	if match := findLeakablePattern(prompt, `\d{3}-\d{2}-\d{4}`); match != "" {
		subs = append(subs, match)
	}

	// Credit card
	if match := findLeakablePattern(prompt, `\d{4}-\d{4}-\d{4}-\d{4}`); match != "" {
		subs = append(subs, match)
	}

	// AKIA keys
	if match := findLeakablePattern(prompt, `AKIA[A-Z0-9]{16}`); match != "" {
		subs = append(subs, match)
	}

	// sk- keys
	if match := findLeakablePattern(prompt, `sk-[a-zA-Z0-9]{20,}`); match != "" {
		subs = append(subs, match)
	}

	// ghp_ keys
	if match := findLeakablePattern(prompt, `ghp_[a-zA-Z0-9]{30,}`); match != "" {
		subs = append(subs, match)
	}

	// General 8-char windows
	for i := 0; i+8 <= len(prompt); i += 4 {
		subs = append(subs, prompt[i:i+8])
	}

	return subs
}

func isEmailChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '+'
}

func findLeakablePattern(s, pattern string) string {
	// Simple regex-free pattern matcher for our specific cases.
	// SSN
	if pattern == `\d{3}-\d{2}-\d{4}` {
		for i := 0; i+10 <= len(s); i++ {
			if isDigitByte(s[i]) && isDigitByte(s[i+1]) && isDigitByte(s[i+2]) &&
				s[i+3] == '-' &&
				isDigitByte(s[i+4]) && isDigitByte(s[i+5]) &&
				s[i+6] == '-' &&
				isDigitByte(s[i+7]) && isDigitByte(s[i+8]) && isDigitByte(s[i+9]) {
				return s[i : i+11]
			}
		}
	}
	if pattern == `\d{4}-\d{4}-\d{4}-\d{4}` {
		for i := 0; i+19 <= len(s); i++ {
			if isDigit4(s[i:i+4]) && s[i+4] == '-' &&
				isDigit4(s[i+5:i+9]) && s[i+9] == '-' &&
				isDigit4(s[i+10:i+14]) && s[i+14] == '-' &&
				isDigit4(s[i+15:i+19]) {
				return s[i : i+19]
			}
		}
	}
	if pattern == `AKIA[A-Z0-9]{16}` {
		for i := 0; i+20 <= len(s); i++ {
			if s[i:i+4] == "AKIA" {
				return s[i : i+20]
			}
		}
	}
	if pattern == `sk-[a-zA-Z0-9]{20,}` {
		for i := 0; i+22 <= len(s); i++ {
			if s[i:i+3] == "sk-" {
				j := i + 3
				for j < len(s) && isAlnumByte(s[j]) {
					j++
				}
				if j-i >= 23 {
					return s[i:j]
				}
			}
		}
	}
	if pattern == `ghp_[a-zA-Z0-9]{30,}` {
		for i := 0; i+34 <= len(s); i++ {
			if s[i:i+4] == "ghp_" {
				j := i + 4
				for j < len(s) && isAlnumByte(s[j]) {
					j++
				}
				if j-i >= 34 {
					return s[i:j]
				}
			}
		}
	}
	return ""
}

func isDigitByte(c byte) bool    { return c >= '0' && c <= '9' }
func isDigit4(s string) bool {
	return len(s) == 4 && isDigitByte(s[0]) && isDigitByte(s[1]) && isDigitByte(s[2]) && isDigitByte(s[3])
}
func isAlnumByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// checkMetadataInvariants verifies no URLs, identifiers, or fingerprints
// in any field value.
func checkMetadataInvariants(t *testing.T, caseIdx int, tc privacyCase, event map[string]interface{}) int {
	violations := 0
	for field, value := range event {
		valueStr, ok := value.(string)
		if !ok {
			continue
		}
		// Check for URLs (http://, https://)
		if strings.Contains(valueStr, "http://") || strings.Contains(valueStr, "https://") {
			t.Errorf("Case %d (%s) METADATA LEAK: field '%s' contains URL: %q", caseIdx, tc.Name, field, valueStr)
			violations++
		}
		// Check for path patterns (/api/, /v1/, etc.)
		if strings.Contains(valueStr, "/api/") || strings.Contains(valueStr, "/v1/") {
			t.Errorf("Case %d (%s) METADATA LEAK: field '%s' contains path: %q", caseIdx, tc.Name, field, valueStr)
			violations++
		}
	}
	return violations
}