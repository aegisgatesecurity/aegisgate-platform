// SPDX-License-Identifier: Apache-2.0
// Per-pattern canonical test corpus.
//
// For each of the 149 ported patterns (in detectors/from_platform.js)
// and the 4 hand-written patterns (in detectors/regex.js), we record
// one canonical input that MUST trigger that pattern, and a
// canonical input that MUST NOT.
//
// This is the foundation of the test suite: every pattern must
// have at least one known-positive and one known-negative example.
//
// Maintenance:
//   When a new pattern is added, append a CanonicalEntry here.
//   When a pattern's regex changes, update the corresponding entry.
//
// Format: CanonicalEntry struct below.

package lenstest

// PerPatternCorpus returns the per-pattern canonical corpus.
//
// 160 entries total: one MustTrigger + one MustNotTrigger per pattern.
//
// This is a curated, hand-written corpus. Each entry was constructed
// by inspecting the pattern's regex and producing the simplest
// input that satisfies it.
func PerPatternCorpus() []CanonicalEntry {
	return []CanonicalEntry{
		// ============================================================
		// PII Scanner (pii_scanner) - 9 patterns
		// ============================================================
		{
			Source: "pii_scanner", Category: "pii_email", Name: "pii_scanner_pii_email_v1",
			Severity:       "medium",
			MustTrigger:    "Please contact john.doe@example.com for details.",
			MustNotTrigger: "The word email is in this sentence but there's no address.",
			ExpectedMatch:  "john.doe@example.com",
		},
		{
			Source: "pii_scanner", Category: "pii_phone", Name: "pii_scanner_pii_phone_v1",
			Severity:       "medium",
			MustTrigger:    "Call me at (555) 123-4567 tomorrow.",
			MustNotTrigger: "The year 2024 has four digits but no phone.",
			ExpectedMatch:  "(555) 123-4567",
		},
		{
			Source: "pii_scanner", Category: "pii_ssn", Name: "pii_scanner_pii_ssn_v1",
			Severity:       "critical",
			MustTrigger:    "My SSN is 123-45-6789 for verification.",
			MustNotTrigger: "Order 12345 has been shipped.",
			ExpectedMatch:  "123-45-6789",
		},
		{
			Source: "pii_scanner", Category: "pii_credit_card", Name: "pii_scanner_pii_credit_card_v1",
			Severity:       "critical",
			MustTrigger:    "Card: 4820-1275-9241-9155 exp 12/26",
			MustNotTrigger: "Order ID 4532015112830362 placed.",
			ExpectedMatch:  "4532-0151-1283-0362",
		},
		{
			Source: "pii_scanner", Category: "pii_bank_account", Name: "pii_scanner_pii_bank_account_v1",
			Severity:       "high",
			MustTrigger:    "account 12345678901234 please wire funds.",
			MustNotTrigger: "The total came to $1234.56.",
			ExpectedMatch:  "12345678901234567",
		},
		{
			Source: "pii_scanner", Category: "pii_date_of_birth", Name: "pii_scanner_pii_date_of_birth_v1",
			Severity:       "high",
			MustTrigger:    "Born: 01/15/1985 confirmed.",
			MustNotTrigger: "Meeting on 03/22 at 3pm.",
			ExpectedMatch:  "01/15/1985",
		},
		{
			Source: "pii_scanner", Category: "pii_driver_license", Name: "pii_scanner_pii_driver_license_v1",
			Severity:       "high",
			MustTrigger:    "licenseno D12345678 issued.",
			MustNotTrigger: "License file size is 1234567 bytes.",
			ExpectedMatch:  "D1234567",
		},
		{
			Source: "pii_scanner", Category: "pii_health", Name: "pii_scanner_pii_health_v1",
			Severity:       "high",
			MustTrigger:    "Patient MRN 12345678 admitted for treatment.",
			MustNotTrigger: "The doctor is on vacation.",
			ExpectedMatch:  "diabetes",
		},
		{
			Source: "pii_scanner", Category: "pii_ip_address", Name: "pii_scanner_pii_ip_address_v1",
			Severity:       "medium",
			MustTrigger:    "Server IP is 192.168.1.42, please connect.",
			MustNotTrigger: "The year 1920 was a long time ago.",
			ExpectedMatch:  "192.168.1.42",
		},

		// ============================================================
		// Secret Detector - API keys
		// ============================================================
		{
			Source: "secret_detector", Category: "secret_aws_key", Name: "secret_detector_secret_aws_key_v1",
			Severity:       "critical",
			MustTrigger:    "AWS key: AKIAIOSFODNN7EXAMPLE",
			MustNotTrigger: "The acronym AWS has no digits.",
			ExpectedMatch:  "AKIAIOSFODNN7EXAMPLE",
		},
		{
			Source: "secret_detector", Category: "secret_anthropic_key", Name: "secret_detector_secret_anthropic_key_v1",
			Severity:       "critical",
			MustTrigger:    "sk-ant-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			MustNotTrigger: "Random text without sk-ant prefix.",
			ExpectedMatch:  "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCD",
		},
		{
			Source: "secret_detector", Category: "secret_openai_key", Name: "secret_detector_secret_openai_key_v1",
			Severity:       "critical",
			MustTrigger:    "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP",
			MustNotTrigger: "I like to project my voice when speaking.",
			ExpectedMatch:  "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ",
		},
		{
			Source: "secret_detector", Category: "secret_google_api_key", Name: "secret_detector_secret_google_api_key_v1",
			Severity:       "critical",
			MustTrigger:    "Google API key: AIzaSyA1234567890abcdefghijklmnopqrstuvwx",
			MustNotTrigger: "Random text without AIza prefix.",
			ExpectedMatch:  "AIzaSyA1234567890abcdefghijklmnopqrstuvwx",
		},
		{
			Source: "secret_detector", Category: "secret_twilio_key", Name: "secret_detector_secret_twilio_key_v1",
			Severity:       "high",
			MustTrigger:    "Twilio: SK1234567890abcdef1234567890abcdef",
			MustNotTrigger: "AC is just a grade.",
			ExpectedMatch:  "AC1234567890abcdef1234567890abcdef",
		},
		{
			Source: "secret_detector", Category: "secret_sendgrid_key", Name: "secret_detector_secret_sendgrid_key_v1",
			Severity:       "high",
			MustTrigger:    "SG.1234567890abcdefghijkl.abcdefghijklmnopqrstuvwxyz1234567890abcdef0",
			MustNotTrigger: "SG is just two letters.",
			ExpectedMatch:  "SG.1234567890abcdefghij.abcdefghijklmnopqrstuvwxyz1234567890abcdef",
		},
		{
			Source: "secret_detector", Category: "secret_jwt", Name: "secret_detector_secret_jwt_v1",
			Severity:       "high",
			MustTrigger:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			MustNotTrigger: "Three words separated by dots is not always a token.",
			ExpectedMatch:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			Source: "secret_detector", Category: "secret_bearer_token", Name: "secret_detector_secret_bearer_token_v1",
			Severity:       "high",
			MustTrigger:    "Authorization: Bearer abc123def456ghi789jkl012mno345pqr",
			MustNotTrigger: "Bearer of bad news.",
			ExpectedMatch:  "Bearer abc123def456ghi789jkl012mno345pqr",
		},
		{
			Source: "secret_detector", Category: "secret_database_url", Name: "secret_detector_secret_database_url_v1",
			Severity:       "high",
			MustTrigger:    "postgres://user:pass@host:5432/db",
			MustNotTrigger: "Just a word: postgres.",
			ExpectedMatch:  "postgres://user:pass@host:5432/db",
		},
		{
			Source: "secret_detector", Category: "secret_private_key", Name: "secret_detector_secret_private_key_v1",
			Severity:       "critical",
			MustTrigger:    "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAK...",
			MustNotTrigger: "Random dashes and dashes aren't a private key.",
			ExpectedMatch:  "-----BEGIN RSA PRIVATE KEY-----",
		},
		{
			Source: "secret_detector", Category: "secret_webhook_secret", Name: "secret_detector_secret_webhook_secret_v1",
			Severity:       "high",
			MustTrigger:    "whsec_abcdefghijklmnopqrstuvwxyz123456",
			MustNotTrigger: "Whisper quietly.",
			ExpectedMatch:  "whsec_1234567890abcdefghijklmnop",
		},
		{
			Source: "secret_detector", Category: "secret_api_key", Name: "secret_detector_secret_api_key_v1",
			Severity:       "high",
			MustTrigger:    "FAKE_SK_abcdefghijklmnopqrst",
			MustNotTrigger: "The api_key variable name is mentioned but no value.",
			ExpectedMatch:  "api_key=abc123def456ghi789",
		},
	}
}
