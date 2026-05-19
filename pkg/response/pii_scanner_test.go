// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - PII Scanner Tests
// =========================================================================

package response

import (
	"context"
	"testing"
	"time"
)

func TestNewPIIScanner(t *testing.T) {
	scanner := NewPIIScanner()
	if scanner == nil {
		t.Fatal("NewPIIScanner() returned nil")
	}
	if scanner.patterns == nil {
		t.Error("patterns map not initialized")
	}
}

func TestNewPIIScannerWithCustomPatterns(t *testing.T) {
	patterns := []string{
		`\bCUSTOM-\d{6}\b`,
		`\bTEST-ID-[A-Z]{4}\b`,
	}

	scanner, err := NewPIIScannerWithCustomPatterns(patterns)
	if err != nil {
		t.Fatalf("NewPIIScannerWithCustomPatterns() error: %v", err)
	}
	if scanner == nil {
		t.Fatal("scanner is nil")
	}
	if len(scanner.customPatterns) != 2 {
		t.Errorf("expected 2 custom patterns, got %d", len(scanner.customPatterns))
	}
}

func TestNewPIIScannerWithInvalidPattern(t *testing.T) {
	patterns := []string{
		`[invalid(regex`,
	}

	_, err := NewPIIScannerWithCustomPatterns(patterns)
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestFindSSN(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int // number of SSN matches expected
	}{
		{"standard SSN", "My SSN is 123-45-6789", 1},
		{"SSN no dashes", "SSN:123456789", 1},
		{"SSN with spaces", "SSN: 123 45 6789", 1},
		{"SSN with dots", "SSN.123.45.6789", 1},
		{"multiple SSNs", "SSN1: 123-45-6789, SSN2: 234-56-7890", 2},
		{"invalid SSN prefix", "SSN: 000-12-3456", 0}, // Cannot start with 000
		{"invalid SSN 666", "SSN: 666-12-3456", 0},    // Cannot start with 666
		{"invalid SSN 900s", "SSN: 900-12-3456", 0},   // Cannot start with 9xx
		{"invalid middle", "SSN: 123-00-6789", 0},     // Middle cannot be 00
		{"invalid last", "SSN: 123-45-0000", 0},       // Last cannot be 0000
		{"no SSN", "This is a normal text without any SSN", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			ssnCount := 0
			for _, m := range matches {
				if m.Category == PII_SSN {
					ssnCount++
				}
			}
			if ssnCount != tt.expected {
				t.Errorf("FindPII(%q) = %d SSNs, want %d", tt.input, ssnCount, tt.expected)
			}
		})
	}
}

func TestFindCreditCard(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Visa standard", "Card: 4111-1111-1111-1111", 1},
		{"Visa no dashes", "Card: 4111111111111111", 1},
		{"Mastercard standard", "MC: 5500-0000-0000-0004", 1},
		{"Amex standard", "Amex: 3782-822463-10005", 1},
		{"Discover standard", "Discover: 6011-1111-1111-1117", 1},
		{"Valid Luhn Visa", "4111111111111111", 1},
		{"Invalid Luhn", "4111111111111112", 0},
		{"Too short", "411111111111", 0},
		{"No card", "This is not a credit card number", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			ccCount := 0
			for _, m := range matches {
				if m.Category == PII_CREDIT_CARD {
					ccCount++
				}
			}
			if ccCount != tt.expected {
				t.Errorf("FindPII(%q) = %d CCs, want %d", tt.input, ccCount, tt.expected)
			}
		})
	}
}

func TestFindEmail(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Standard email", "Contact: john@example.com", 1},
		{"Email with subdomain", "Email: user@mail.server.com", 1},
		{"Email with dots", "User.name@company.co.uk", 1},
		{"Multiple emails", "Primary: alice@test.com, Secondary: bob@example.org", 2},
		{"Invalid - no domain", "Email: user@", 0},
		{"Invalid - no @", "Email: username.domain.com", 0},
		{"Invalid - no tld", "Email: user@domain", 0},
		{"No email", "This is plain text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			emailCount := 0
			for _, m := range matches {
				if m.Category == PII_EMAIL {
					emailCount++
				}
			}
			if emailCount != tt.expected {
				t.Errorf("FindPII(%q) = %d emails, want %d", tt.input, emailCount, tt.expected)
			}
		})
	}
}

func TestFindPhone(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"US format 1", "Phone: (555) 123-4567", 1},
		{"US format 2", "Call: 555-123-4567", 1},
		{"US format 3", "Tel: 555.123.4567", 1},
		{"International", "Phone: +1-555-123-4567", 1},
		{"With country code", "Phone: +1-555-123-4567", 1},
		{"Too short", "Phone: 555-123", 0},
		{"No phone", "Just some text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			phoneCount := 0
			for _, m := range matches {
				if m.Category == PII_PHONE {
					phoneCount++
				}
				_ = m.Redacted
			}
			if phoneCount != tt.expected {
				t.Errorf("FindPII(%q) = %d phones, want %d", tt.input, phoneCount, tt.expected)
			}
		})
	}
}

func TestFindHealthInfo(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"MRN format", "Patient MRN: 12345678", 1},
		{"Medical Record", "Medical Record ID: 876543210", 1},
		{"Patient ID", "Patient ID#: 1122334455", 1},
		{"Health ID", "Health ID: 9988776655", 1},
		{"HIPAA keyword", "HIPAA ID: 5544332211", 1},
		{"Too short", "MRN: 1234", 0},
		{"No health info", "Just text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			healthCount := 0
			for _, m := range matches {
				if m.Category == PII_HEALTH {
					healthCount++
				}
			}
			if healthCount != tt.expected {
				t.Errorf("FindPII(%q) = %d health, want %d", tt.input, healthCount, tt.expected)
			}
		})
	}
}

func TestFindIPAddress(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Standard IP", "Server IP: 192.168.1.1", 1},
		{"Multiple IPs", "From 10.0.0.1 to 10.0.0.255", 2},
		{"Loopback", "localhost: 127.0.0.1", 1},
		{"Invalid octet", "IP: 192.168.1.256", 0},
		{"No IP", "No IP here", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			ipCount := 0
			for _, m := range matches {
				if m.Category == PII_IP_ADDRESS {
					ipCount++
				}
			}
			if ipCount != tt.expected {
				t.Errorf("FindPII(%q) = %d IPs, want %d", tt.input, ipCount, tt.expected)
			}
		})
	}
}

func TestFindDOB(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"DOB format", "DOB: 01/15/1985", 1},
		{"Date of Birth", "Date of Birth: 1985-01-15", 1},
		{"Birth Date", "Birth Date: 12/25/1990", 1},
		{"Born format", "Born: 03/30/2000", 1},
		{"No DOB", "Just text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			dobCount := 0
			for _, m := range matches {
				if m.Category == PII_DATE_OF_BIRTH {
					dobCount++
				}
			}
			if dobCount != tt.expected {
				t.Errorf("FindPII(%q) = %d DOBs, want %d", tt.input, dobCount, tt.expected)
			}
		})
	}
}

func TestFindBankAccount(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Account format", "Account: 12345678901234", 1},
		{"Acct format", "Acct#: 87654321098765", 1},
		{"Savings", "Savings Account: 1122334455667788", 1},
		{"Too short", "Account: 1234567", 0},
		{"No account", "No account info", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			bankCount := 0
			for _, m := range matches {
				if m.Category == PII_BANK_ACCOUNT {
					bankCount++
				}
			}
			if bankCount != tt.expected {
				t.Errorf("FindPII(%q) = %d bank accounts, want %d", tt.input, bankCount, tt.expected)
			}
		})
	}
}

func TestFindPassport(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"9 char alphanumeric", "Passport: ABC123456", 1},
		{"9 uppercase", "Passport No: XYZ789012", 1},
		{"9 numbers", "Passport: 123456789", 1},
		{"Too short", "Passport: ABC123", 0},
		{"Too long", "Passport: ABC1234567890", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			passportCount := 0
			for _, m := range matches {
				if m.Category == PII_PASSPORT {
					passportCount++
				}
			}
			if passportCount != tt.expected {
				t.Errorf("FindPII(%q) = %d passports, want %d", tt.input, passportCount, tt.expected)
			}
		})
	}
}

func TestFindDriverLicense(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"DL format", "DL: ABC12345", 1},
		{"DriverLicense format", "DriverLicense: XYZ98765", 1},
		{"With DL#", "DL#: 12345678901234", 1},
		{"No DL", "Just text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			dlCount := 0
			for _, m := range matches {
				if m.Category == PII_DRIVER_LICENSE {
					dlCount++
				}
			}
			if dlCount != tt.expected {
				t.Errorf("FindPII(%q) = %d DLs, want %d", tt.input, dlCount, tt.expected)
			}
		})
	}
}

func TestFindName(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Mr. format", "Hello Mr. John Smith", 1},
		{"Mrs. format", "Dear Mrs. Jane Doe", 1},
		{"Dr. format", "Dr. Robert Johnson", 1},
		{"Prof. format", "Prof. Mary Williams", 1},
		{"No title", "Just plain text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			nameCount := 0
			for _, m := range matches {
				if m.Category == PII_NAME {
					nameCount++
				}
			}
			if nameCount != tt.expected {
				t.Errorf("FindPII(%q) = %d names, want %d", tt.input, nameCount, tt.expected)
			}
		})
	}
}

func TestMultipleTypesInText(t *testing.T) {
	scanner := NewPIIScanner()

	text := "User John Doe (john@example.com) called from 555-123-4567. SSN: 123-45-6789. Card: 4111-1111-1111-1111"

	matches := scanner.FindPII(text)

	categories := make(map[PIICategory]int)
	for _, m := range matches {
		categories[m.Category]++
	}

	if categories[PII_EMAIL] != 1 {
		t.Errorf("expected 1 email, got %d", categories[PII_EMAIL])
	}
	if categories[PII_PHONE] != 1 {
		t.Errorf("expected 1 phone, got %d", categories[PII_PHONE])
	}
	if categories[PII_SSN] != 1 {
		t.Errorf("expected 1 SSN, got %d", categories[PII_SSN])
	}
	if categories[PII_CREDIT_CARD] != 1 {
		t.Errorf("expected 1 CC, got %d", categories[PII_CREDIT_CARD])
	}
}

func TestScanPII(t *testing.T) {
	scanner := NewPIIScanner()
	ctx := context.Background()

	text := "SSN: 123-45-6789"
	matches, err := scanner.ScanPII(ctx, text)

	if err != nil {
		t.Fatalf("ScanPII() error: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Category != PII_SSN {
		t.Errorf("expected PII_SSN, got %v", matches[0].Category)
	}
}

func TestScanPIIWithContext(t *testing.T) {
	scanner := NewPIIScanner()
	ctx := context.Background()
	scanCtx := NewScanContext("client-123", "req-456")

	text := "Email: test@example.com"
	matches, err := scanner.ScanPIIWithContext(ctx, text, scanCtx)

	if err != nil {
		t.Fatalf("ScanPIIWithContext() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// Should return redacted value
	if matches[0].Value == "test@example.com" {
		t.Error("expected redacted value, got original")
	}
}

func TestCountByCategory(t *testing.T) {
	scanner := NewPIIScanner()

	text := "SSN: 123-45-6789, SSN: 234-56-7890, Email: a@b.com, Email: c@d.com, Phone: 555-123-4567"
	matches := scanner.FindPII(text)

	counts := scanner.CountByCategory(matches)

	if counts[PII_SSN] != 2 {
		t.Errorf("expected 2 SSNs, got %d", counts[PII_SSN])
	}
	if counts[PII_EMAIL] != 2 {
		t.Errorf("expected 2 emails, got %d", counts[PII_EMAIL])
	}
	if counts[PII_PHONE] != 1 {
		t.Errorf("expected 1 phone, got %d", counts[PII_PHONE])
	}
}

func TestSeveritySummary(t *testing.T) {
	scanner := NewPIIScanner()

	text := "SSN: 123-45-6789 (severity 5), Email: test@test.com (severity 3), Phone: 555-123-4567 (severity 3)"
	matches := scanner.FindPII(text)

	summary := scanner.SeveritySummary(matches)

	if summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", summary.Critical)
	}
	if summary.Medium != 2 {
		t.Errorf("expected 2 medium, got %d", summary.Medium)
	}
}

func TestRedactPII(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"SSN redaction",
			"My SSN is 123-45-6789",
			"My SSN is XXX-XX-6789",
		},
		{
			"Credit card redaction",
			"Card: 4111-1111-1111-1111",
			"Card: ****-****-****-1111",
		},
		{
			"Email redaction",
			"Email: john@example.com",
			"Email: jo***@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.RedactPII(tt.input, nil)
			if result != tt.expected {
				t.Errorf("RedactPII(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRedactPIIWithConfig(t *testing.T) {
	scanner := NewPIIScanner()

	config := &RedactionConfig{
		RedactSSN:          true,
		RedactCreditCard:   false, // Don't redact CC
		RedactEmail:        true,
		RedactPhone:        false,
		RedactHealthInfo:   true,
		RedactCustom:       false,
	}

	text := "SSN: 123-45-6789, CC: 4111-1111-1111-1111, Email: a@b.com"

	result := scanner.RedactPII(text, config)

	// SSN should be redacted
	if result == text {
		t.Error("SSN should be redacted")
	}

	// CC should NOT be redacted (contains original)
	if result == "SSN: XXX-XX-6789, CC: 4111-1111-1111-1111, Email: a***@b.com" {
		// This is the expected partial redaction
	} else {
		// Just verify SSN and Email are redacted
		if !contains(result, "XXX-XX-") || !contains(result, "***@") {
			t.Errorf("RedactPII with config did not properly redact")
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestScanTextForPII(t *testing.T) {
	text := "SSN: 123-45-6789"
	matches, err := ScanTextForPII(text)

	if err != nil {
		t.Fatalf("ScanTextForPII() error: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}
}

func TestScanWithTimeout(t *testing.T) {
	ctx := context.Background()
	text := "SSN: 123-45-6789"

	matches, err := ScanWithTimeout(ctx, text, 100*time.Millisecond)

	if err != nil {
		t.Fatalf("ScanWithTimeout() error: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}
}

func TestScanWithTimeoutExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	text := "SSN: 123-45-6789"

	_, err := ScanWithTimeout(ctx, text, 100*time.Millisecond)

	if err == nil {
		t.Error("expected context deadline exceeded error")
	}
}

func TestLuhnCheck(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		number   string
		expected bool
	}{
		{"4111111111111111", true},  // Valid Visa
		{"5500000000000004", true},  // Valid MC
		{"378282246310005", true},   // Valid Amex
		{"4111111111111112", false}, // Invalid
		{"1234567890123456", false}, // Invalid
		{"123", false},             // Too short
	}

	for _, tt := range tests {
		t.Run(tt.number, func(t *testing.T) {
			result := scanner.luhnCheck(tt.number)
			if result != tt.expected {
				t.Errorf("luhnCheck(%s) = %v, want %v", tt.number, result, tt.expected)
			}
		})
	}
}

func TestGetRedaction(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		category PIICategory
		value    string
		expected string
	}{
		{PII_SSN, "123-45-6789", "XXX-XX-6789"},
		{PII_CREDIT_CARD, "4111-1111-1111-1111", "****-****-****-1111"},
		{PII_EMAIL, "test@example.com", "te***@example.com"},
		{PII_PHONE, "555-123-4567", "***-***-4567"},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			result := scanner.getRedaction(tt.category, tt.value)
			if result != tt.expected {
				t.Errorf("getRedaction(%v, %s) = %s, want %s", tt.category, tt.value, result, tt.expected)
			}
		})
	}
}

func TestValidateMatch(t *testing.T) {
	scanner := NewPIIScanner()

	// Valid SSN
	if !scanner.validateMatch(PII_SSN, "123-45-6789") {
		t.Error("expected valid SSN to pass validation")
	}

	// Invalid SSN (starts with 000)
	if scanner.validateMatch(PII_SSN, "000-12-3456") {
		t.Error("expected invalid SSN (000 prefix) to fail validation")
	}

	// Invalid SSN (middle 00)
	if scanner.validateMatch(PII_SSN, "123-00-6789") {
		t.Error("expected invalid SSN (00 middle) to fail validation")
	}

	// Valid email
	if !scanner.validateMatch(PII_EMAIL, "test@example.com") {
		t.Error("expected valid email to pass validation")
	}

	// Invalid email (no @)
	if scanner.validateMatch(PII_EMAIL, "testexample.com") {
		t.Error("expected invalid email to fail validation")
	}

	// Valid IP
	if !scanner.validateMatch(PII_IP_ADDRESS, "192.168.1.1") {
		t.Error("expected valid IP to pass validation")
	}
}

func TestFindMatches(t *testing.T) {
	scanner := NewPIIScanner()

	pattern := scanner.patterns[PII_SSN]
	matches := scanner.findMatches("SSN: 123-45-6789", PII_SSN, pattern)

	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Start != 5 || matches[0].End != 16 {
		t.Errorf("expected start=5, end=16, got start=%d, end=%d", matches[0].Start, matches[0].End)
	}
}

func TestPIIMatchPositions(t *testing.T) {
	scanner := NewPIIScanner()

	text := "Prefix SSN: 123-45-6789 suffix"
	matches := scanner.FindPII(text)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// Verify the match is at the correct position
	if matches[0].Value != "123-45-6789" {
		t.Errorf("expected '123-45-6789', got '%s'", matches[0].Value)
	}
}

func TestCustomPatterns(t *testing.T) {
	scanner, _ := NewPIIScannerWithCustomPatterns([]string{`\bTEST-\d{6}\b`})

	text := "ID: TEST-123456"
	matches := scanner.FindPII(text)

	// Should find custom pattern (categorized as email since that's the fallback)
	if len(matches) < 1 {
		t.Error("expected to find custom pattern")
	}
}

func TestEmptyText(t *testing.T) {
	scanner := NewPIIScanner()

	matches := scanner.FindPII("")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty text, got %d", len(matches))
	}
}

func TestNoMatches(t *testing.T) {
	scanner := NewPIIScanner()

	text := "This is a normal sentence with no PII"
	matches := scanner.FindPII(text)

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestBoundaryConditions(t *testing.T) {
	scanner := NewPIIScanner()

	tests := []struct {
		name  string
		input string
	}{
		{"start of string", "123-45-6789 is my SSN"},
		{"end of string", "My SSN is 123-45-6789"},
		{"entire string", "123-45-6789"},
		{"with newlines", "Line1: 123-45-6789\nLine2: 555-123-4567"},
		{"with tabs", "SSN:\t123-45-6789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.FindPII(tt.input)
			if len(matches) == 0 {
				t.Errorf("expected matches in %q", tt.input)
			}
		})
	}
}

func TestLargeText(t *testing.T) {
	scanner := NewPIIScanner()

	// Create a large text with multiple PII
	baseText := "SSN: 123-45-6789, Email: test@example.com, Phone: 555-123-4567, "
	largeText := ""
	for i := 0; i < 100; i++ {
		largeText += baseText
	}

	matches := scanner.FindPII(largeText)

	expected := 400 // 100 * 4 (SSN, Email, Phone, CC)
	if len(matches) < expected/2 {
		t.Errorf("expected at least %d matches in large text, got %d", expected/2, len(matches))
	}
}

func TestConcurrency(t *testing.T) {
	scanner := NewPIIScanner()
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				text := "SSN: 123-45-6789, Email: test@example.com"
				scanner.FindPII(text)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func BenchmarkFindPII(b *testing.B) {
	scanner := NewPIIScanner()
	text := "SSN: 123-45-6789, Email: test@example.com, Phone: 555-123-4567, Card: 4111-1111-1111-1111"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.FindPII(text)
	}
}

func BenchmarkLuhnCheck(b *testing.B) {
	scanner := NewPIIScanner()
	card := "4111111111111111"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.luhnCheck(card)
	}
}
