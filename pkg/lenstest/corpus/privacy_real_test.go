//go:build manual

// +build manual


// Privacy boundary test: actual API client + captured HTTP requests.
//
// Runs the Lens api/client.js (built into /tmp/lens-FINAL28) with
// a mock fetch, sends 14 adversarial events, captures the actual
// HTTP requests, and inspects them for:
//
//  1. SCHEMA: every field in the request body is in the allowlist
//     (8 required + 1 optional id, no extras)
//  2. PROMPT: no prompt text appears in any field value
//  3. METADATA: no URLs, no bearer tokens in body
//
// This is the rigorous test that proves the privacy invariant
// in the ACTUAL CODE, not synthetic fixtures.
//
// Failure here means the Lens cannot ship v0.1. The test is
// non-negotiable per the privacy policy §10.2.
package lenstest_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// promptCases is the set of (prompt, category) pairs we send through
// the actual API client. The prompts contain sensitive data (PII,
// secrets); the categories tell the detector how to label them.
var promptCases = []struct {
	Prompt   string
	Category string
}{
	{"Contact john.doe@example.com for details", "pii_email"},
	{"My SSN is 123-45-6789 please verify", "pii_ssn"},
	{"Card 4532-0151-1283-0362 exp 12/26", "pii_credit_card"},
	{"AWS key AKIAIOSFODNN7EXAMPLE", "secret_api_key"},
	{"Auth token: Bearer abc123def456ghi789jkl012mno345", "secret_api_key"},
	{"GitHub token ghp_16C7e42F292c6912E7710c838347Ae178B4a", "secret_api_key"},
	{"JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "secret_api_key"},
	{"postgres://user:password@host:5432/db", "secret_api_key"},
	{"Phone 555-123-4567 call me", "pii_phone"},
	{"Address: 123 Main St, Springfield, IL 62701", "pii_email"},
	{"DOB 01/15/1985", "pii_email"},
	{"Bank account 12345678901234 routing 021000021", "pii_email"},
	{"Driver license D12345678", "pii_email"},
	{"My WiFi password is MySecret123!", "secret_api_key"},
}

// TestPrivacyBoundary_RealClient runs the actual Lens API client
// with a mock fetch, captures all HTTP requests, and verifies
// the privacy invariants.
func TestPrivacyBoundary_RealClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-client privacy test in -short mode")
	}

	// Build the corpus JSON for the Python script
	casesJSON, _ := json.Marshal(promptCases)

	// Run the Python script that exercises the actual API client
	cmd := exec.Command("python3", "/tmp/test_privacy_boundary.py")
	cmd.Stdin = strings.NewReader(string(casesJSON))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Python output:\n%s", string(output))
		t.Fatalf("Privacy test failed to run: %v", err)
	}

	t.Logf("\n=== Real-Client Privacy Boundary Report ===")
	t.Logf("\n%s", string(output))

	// Parse the Python output for pass/fail
	if !strings.Contains(string(output), "[PASS]") {
		t.Errorf("Privacy boundary test FAILED. See output above.")
	}
}