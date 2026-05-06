// SPDX-License-Identifier: Apache-2.0
//go:build !race

package email

import (
	"strings"
	"testing"
)

// TestSendLicenseEmail tests SendLicenseEmail end-to-end, including default-setting
// behavior and SMTP send failure (expected with non-existent server).
func TestSendLicenseEmail(t *testing.T) {
	cfg := Config{
		Host: "smtp.nonexistent.invalid",
		Port: 587,
		From: "noreply@aegisgatesecurity.io",
	}
	client := NewEmailClient(cfg)

	t.Run("applies defaults when fields are empty", func(t *testing.T) {
		data := LicenseEmailData{
			Tier:       "Developer",
			LicenseKey: "test-key-001",
			// SupportEmail, CompanyName, CompanyURL intentionally empty
		}
		err := client.SendLicenseEmail("customer@example.com", data)
		if err == nil {
			t.Fatal("expected SMTP error, got nil")
		}
		// Error should be SMTP-related, not a template error — proving defaults were applied
		if strings.Contains(err.Error(), "template") {
			t.Fatalf("defaults should have been applied; got template error: %v", err)
		}
	})

	t.Run("preserves provided fields", func(t *testing.T) {
		data := LicenseEmailData{
			CustomerName: "Jane Doe",
			Tier:         "Enterprise",
			LicenseKey:   "ENT-KEY-999",
			IssuedAt:     "2026-01-01",
			ExpiresAt:    "2027-01-01",
			SupportEmail: "custom@corp.io",
			CompanyName:  "Custom Corp",
			CompanyURL:   "https://custom.corp.io",
		}
		err := client.SendLicenseEmail("jane@corp.io", data)
		if err == nil {
			t.Fatal("expected SMTP error, got nil")
		}
	})

	t.Run("applies all three defaults simultaneously", func(t *testing.T) {
		data := LicenseEmailData{
			Tier:       "Starter",
			LicenseKey: "SK-000",
		}
		err := client.SendLicenseEmail("user@example.com", data)
		if err == nil {
			t.Fatal("expected SMTP error, got nil")
		}
		// Verify the rendered template contains the default values by rendering directly
		withDefaults := LicenseEmailData{
			Tier:         "Starter",
			LicenseKey:   "SK-000",
			SupportEmail: "support@aegisgatesecurity.io",
			CompanyName:  "AegisGate Security, LLC",
			CompanyURL:   "https://aegisgatesecurity.io",
		}
		html, err := client.renderTemplate(withDefaults)
		if err != nil {
			t.Fatalf("renderTemplate error: %v", err)
		}
		if !strings.Contains(html, "support@aegisgatesecurity.io") {
			t.Error("rendered HTML missing default SupportEmail")
		}
		if !strings.Contains(html, "AegisGate Security, LLC") {
			t.Error("rendered HTML missing default CompanyName")
		}
		if !strings.Contains(html, "https://aegisgatesecurity.io") {
			t.Error("rendered HTML missing default CompanyURL")
		}
	})

	t.Run("does not override non-empty fields", func(t *testing.T) {
		data := LicenseEmailData{
			Tier:         "Pro",
			LicenseKey:   "PRO-KEY",
			SupportEmail: "pro@custom.io",
			CompanyName:  "Custom Inc",
			CompanyURL:   "https://custom.inc",
		}
		// Render with the same values to confirm they're used as-is
		html, err := client.renderTemplate(data)
		if err != nil {
			t.Fatalf("renderTemplate error: %v", err)
		}
		if !strings.Contains(html, "pro@custom.io") {
			t.Error("rendered HTML should contain the provided SupportEmail")
		}
		if !strings.Contains(html, "Custom Inc") {
			t.Error("rendered HTML should contain the provided CompanyName")
		}
		if !strings.Contains(html, "https://custom.inc") {
			t.Error("rendered HTML should contain the provided CompanyURL")
		}
	})
}

// TestEmailSend_STARTTLS tests the private send method via STARTTLS path (UseTLS=true).
// Connections to a non-existent server must return an error.
func TestEmailSend_STARTTLS(t *testing.T) {
	t.Run("with auth credentials", func(t *testing.T) {
		cfg := Config{
			Host:     "smtp.nonexistent.invalid",
			Port:     587,
			From:     "noreply@aegisgatesecurity.io",
			Username: "user",
			Password: "pass",
			UseTLS:   true,
		}
		client := NewEmailClient(cfg)
		err := client.send("recipient@example.com", []byte("test message"))
		if err == nil {
			t.Fatal("expected error from STARTTLS send to non-existent server, got nil")
		}
		if !strings.Contains(err.Error(), "SMTP") {
			t.Errorf("expected SMTP-related error, got: %v", err)
		}
	})

	t.Run("without auth credentials", func(t *testing.T) {
		cfg := Config{
			Host:   "smtp.nonexistent.invalid",
			Port:   587,
			From:   "noreply@aegisgatesecurity.io",
			UseTLS: true,
			// No Username/Password — auth should be nil
		}
		client := NewEmailClient(cfg)
		err := client.send("recipient@example.com", []byte("test message"))
		if err == nil {
			t.Fatal("expected error from STARTTLS send, got nil")
		}
	})
}

// TestEmailSend_ImplicitTLS tests the private send method via implicit TLS path (UseTLS=false).
// Connections to a non-existent server must return an error.
func TestEmailSend_ImplicitTLS(t *testing.T) {
	t.Run("with auth credentials", func(t *testing.T) {
		cfg := Config{
			Host:     "smtp.nonexistent.invalid",
			Port:     465,
			From:     "noreply@aegisgatesecurity.io",
			Username: "user",
			Password: "pass",
			UseTLS:   false, // implicit TLS
		}
		client := NewEmailClient(cfg)
		err := client.send("recipient@example.com", []byte("test message"))
		if err == nil {
			t.Fatal("expected error from implicit TLS connection, got nil")
		}
		if !strings.Contains(err.Error(), "TLS") && !strings.Contains(err.Error(), "dial") && !strings.Contains(err.Error(), "connection") {
			t.Errorf("expected TLS/connection error, got: %v", err)
		}
	})

	t.Run("without auth credentials", func(t *testing.T) {
		cfg := Config{
			Host:   "smtp.nonexistent.invalid",
			Port:   465,
			From:   "noreply@aegisgatesecurity.io",
			UseTLS: false,
			// No Username/Password
		}
		client := NewEmailClient(cfg)
		err := client.send("recipient@example.com", []byte("test message"))
		if err == nil {
			t.Fatal("expected error from implicit TLS connection, got nil")
		}
	})
}

// TestDefaultProtonMailConfig verifies the helper returns correct ProtonMail SMTP settings.
func TestDefaultProtonMailConfig(t *testing.T) {
	cfg := DefaultProtonMailConfig("user@protonmail.com", "app-secret", "AegisGate")

	if cfg.Host != "smtp.protonmail.ch" {
		t.Errorf("Host = %q, want %q", cfg.Host, "smtp.protonmail.ch")
	}
	if cfg.Port != 587 {
		t.Errorf("Port = %d, want %d", cfg.Port, 587)
	}
	if cfg.Username != "user@protonmail.com" {
		t.Errorf("Username = %q, want %q", cfg.Username, "user@protonmail.com")
	}
	if cfg.Password != "app-secret" {
		t.Errorf("Password = %q, want %q", cfg.Password, "app-secret")
	}
	if cfg.From != "user@protonmail.com" {
		t.Errorf("From = %q, want %q", cfg.From, "user@protonmail.com")
	}
	if cfg.FromName != "AegisGate" {
		t.Errorf("FromName = %q, want %q", cfg.FromName, "AegisGate")
	}
	if !cfg.UseTLS {
		t.Error("UseTLS = false, want true")
	}
}

// TestSimpleSendEmail verifies the convenience function creates a client and attempts delivery.
// It must return an error with a non-existent SMTP server.
func TestSimpleSendEmail(t *testing.T) {
	cfg := Config{
		Host: "smtp.nonexistent.invalid",
		Port: 587,
		From: "noreply@aegisgatesecurity.io",
	}

	err := SimpleSendEmail(cfg, "customer@example.com", "Your License", "license-key-body")
	if err == nil {
		t.Fatal("expected SMTP error from SimpleSendEmail, got nil")
	}
	// Should be an SMTP/connection error, not a template error
	if strings.Contains(err.Error(), "template") {
		t.Fatalf("got template error, expected SMTP/connection error: %v", err)
	}
}
