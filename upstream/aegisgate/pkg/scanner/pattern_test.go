// Package scanner_test provides unit tests for the scanner package.
// Tests pattern matching for sensitive data detection.
//
//go:build !integration
// +build !integration

package scanner_test

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"
)

func TestCreditCardDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"Visa card", "4532015112830366", true},
		{"Mastercard", "5555555555554444", true},
		{"Amex", "378282246310005", true},
		{"Random", "1234567890123456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestSSNDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"SSN with dashes", "123-45-6789", true},
		{"SSN without dashes", "123456789", true},
		{"Random", "1234567890", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestEmailDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("user@example.com")
	if len(findings) == 0 {
		t.Error("Expected to find email")
	}
}

func TestAWSAccessKeyDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("AKIAIOSFODNN7EXAMPLE")
	if len(findings) == 0 {
		t.Error("Expected to find AWS key")
	}
}

func TestGitHubTokenDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"Classic token", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true},
		{"OAuth token", "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true},
		{"Invalid", "ghx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestJWTTokenDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	if len(findings) == 0 {
		t.Error("Expected to find JWT")
	}
}

func TestPrivateKeyDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"RSA key", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"EC key", "-----BEGIN EC PRIVATE KEY-----", true},
		{"OpenSSH key", "-----BEGIN OPENSSH PRIVATE KEY-----", true},
		{"Cert", "-----BEGIN CERTIFICATE-----", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestConnectionStringDetection(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	tests := []struct {
		name    string
		content string
		find    bool
	}{
		{"PostgreSQL", "postgresql://user:pass@localhost:5432/db", true},
		{"MySQL", "mysql://user:pass@localhost:3306/db", true},
		{"MongoDB", "mongodb://localhost:27017", true},
		{"Redis", "redis://localhost:6379", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := sc.Scan(tt.content)
			hasFinding := len(findings) > 0
			if hasFinding != tt.find {
				t.Errorf("Scan() = %v, want %v", hasFinding, tt.find)
			}
		})
	}
}

func TestSeverityConstants(t *testing.T) {
	if scanner.Info.String() != "Info" {
		t.Errorf("Expected Info, got %s", scanner.Info.String())
	}
	if scanner.Low.String() != "Low" {
		t.Errorf("Expected Low, got %s", scanner.Low.String())
	}
	if scanner.Medium.String() != "Medium" {
		t.Errorf("Expected Medium, got %s", scanner.Medium.String())
	}
	if scanner.High.String() != "High" {
		t.Errorf("Expected High, got %s", scanner.High.String())
	}
	if scanner.Critical.String() != "Critical" {
		t.Errorf("Expected Critical, got %s", scanner.Critical.String())
	}
}

func TestShouldBlock(t *testing.T) {
	tests := []struct {
		severity scanner.Severity
		expected bool
	}{
		{scanner.Info, false},
		{scanner.Low, false},
		{scanner.Medium, false},
		{scanner.High, true},
		{scanner.Critical, true},
	}

	for _, tt := range tests {
		result := scanner.ShouldBlock(tt.severity)
		if result != tt.expected {
			t.Errorf("ShouldBlock(%v) = %v, want %v", tt.severity, result, tt.expected)
		}
	}
}

func TestCategoryConstants(t *testing.T) {
	if string(scanner.CategoryPII) != "PII" {
		t.Errorf("Expected PII, got %s", scanner.CategoryPII)
	}
	if string(scanner.CategoryCredential) != "Credential" {
		t.Errorf("Expected Credential, got %s", scanner.CategoryCredential)
	}
	if string(scanner.CategoryFinancial) != "Financial" {
		t.Errorf("Expected Financial, got %s", scanner.CategoryFinancial)
	}
	if string(scanner.CategoryCryptographic) != "Cryptographic" {
		t.Errorf("Expected Cryptographic, got %s", scanner.CategoryCryptographic)
	}
	if string(scanner.CategoryNetwork) != "Network" {
		t.Errorf("Expected Network, got %s", scanner.CategoryNetwork)
	}
}

func TestDefaultPatterns(t *testing.T) {
	patterns := scanner.DefaultPatterns()
	if len(patterns) == 0 {
		t.Error("Expected at least one pattern")
	}

	// Check first pattern has required fields
	p := patterns[0]
	if p.Name == "" {
		t.Error("Expected pattern to have a name")
	}
	if p.Regex == nil {
		t.Error("Expected pattern to have a regex")
	}
}

func TestScannerWithNilPatterns(t *testing.T) {
	cfg := &scanner.Config{
		Patterns:       nil,
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("some content")
	// Should not panic
	_ = findings
}

func TestFindingHasNoFields(t *testing.T) {
	// Finding struct only has Pattern, Match, Position, Context
	// No direct fields for Severity, Name, etc.
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
	}
	sc := scanner.New(cfg)

	findings := sc.Scan("test@example.com")
	for _, f := range findings {
		// These fields exist on Finding
		_ = f.Pattern
		_ = f.Match
		_ = f.Position
		_ = f.Context
	}
}
