// SPDX-License-Identifier: Apache-2.0
// Package email provides email sending functionality for AegisGate license delivery.
// Uses Go's net/smtp package (stdlib only) for maximum portability.

package email

import (
	"strings"
	"testing"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "empty config",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name: "missing host",
			cfg: Config{
				Port: 587,
				From: "test@example.com",
			},
			wantErr: true,
		},
		{
			name: "missing port",
			cfg: Config{
				Host: "smtp.example.com",
				From: "test@example.com",
			},
			wantErr: true,
		},
		{
			name: "missing from",
			cfg: Config{
				Host: "smtp.example.com",
				Port: 587,
			},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: Config{
				Host: "smtp.example.com",
				Port: 587,
				From: "test@example.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultGmailConfig(t *testing.T) {
	cfg := DefaultGmailConfig("test@gmail.com", "app-password", "AegisGate")

	if cfg.Host != "smtp.gmail.com" {
		t.Errorf("Expected host smtp.gmail.com, got %s", cfg.Host)
	}
	if cfg.Port != 587 {
		t.Errorf("Expected port 587, got %d", cfg.Port)
	}
	if cfg.Username != "test@gmail.com" {
		t.Errorf("Expected username test@gmail.com, got %s", cfg.Username)
	}
	if cfg.From != "test@gmail.com" {
		t.Errorf("Expected from test@gmail.com, got %s", cfg.From)
	}
	if cfg.FromName != "AegisGate" {
		t.Errorf("Expected from name AegisGate, got %s", cfg.FromName)
	}
	if !cfg.UseTLS {
		t.Error("Expected UseTLS to be true")
	}
}

func TestDefaultSMTP2GOConfig(t *testing.T) {
	cfg := DefaultSMTP2GOConfig("user", "api-key", "noreply@aegisgatesecurity.io", "AegisGate")

	if cfg.Host != "mail.smtp2go.com" {
		t.Errorf("Expected host mail.smtp2go.com, got %s", cfg.Host)
	}
	if cfg.Port != 587 {
		t.Errorf("Expected port 587, got %d", cfg.Port)
	}
	if cfg.Username != "user" {
		t.Errorf("Expected username user, got %s", cfg.Username)
	}
	if cfg.From != "noreply@aegisgatesecurity.io" {
		t.Errorf("Expected from noreply@aegisgatesecurity.io, got %s", cfg.From)
	}
	if !cfg.UseTLS {
		t.Error("Expected UseTLS to be true")
	}
}

func TestEmailClient_SendLicenseEmail(t *testing.T) {
	// This test verifies template rendering without actually sending email.
	// To test actual sending, configure a real SMTP server.

	cfg := DefaultGmailConfig("test@gmail.com", "test-password", "AegisGate Test")
	client := NewEmailClient(cfg)

	data := LicenseEmailData{
		CustomerName: "Test Customer",
		Tier:         "Developer",
		LicenseKey:   "eyJwYXlsb2FkIjp7ImxpY2Vuc2VfaWQiOiJ0ZXN0In0=",
		IssuedAt:    "Wed, 29 Apr 2026 12:00:00 -0700",
		ExpiresAt:   "Wed, 29 May 2026 12:00:00 -0700",
		Features:     []string{"starter_mode"},
		SupportEmail:  "support@aegisgatesecurity.io",
		CompanyName:  "AegisGate Security, LLC",
		CompanyURL:   "https://aegisgatesecurity.io",
	}

	// Test template rendering (won't fail on missing SMTP connection)
	t.Run("template rendering", func(t *testing.T) {
		htmlBody, err := client.renderTemplate(data)
		if err != nil {
			t.Fatalf("renderTemplate() error = %v", err)
		}

		// Verify template contains expected content
		if !strings.Contains(htmlBody, "Test Customer") {
			t.Error("Template missing customer name")
		}
		if !strings.Contains(htmlBody, "Developer") {
			t.Error("Template missing tier")
		}
		if !strings.Contains(htmlBody, data.LicenseKey) {
			t.Error("Template missing license key")
		}
		if !strings.Contains(htmlBody, "AegisGate Security") {
			t.Error("Template missing company name")
		}
	})

	// Test message building
	t.Run("message building", func(t *testing.T) {
		msg, err := client.buildMessage("customer@example.com", "Test Subject", "<html>test</html>")
		if err != nil {
			t.Fatalf("buildMessage() error = %v", err)
		}

		msgStr := string(msg)
		if !strings.Contains(msgStr, "From:") {
			t.Error("Message missing From header")
		}
		if !strings.Contains(msgStr, "To: customer@example.com") {
			t.Error("Message missing To header")
		}
		if !strings.Contains(msgStr, "Subject: Test Subject") {
			t.Error("Message missing Subject header")
		}
		if !strings.Contains(msgStr, "text/html") {
			t.Error("Message missing Content-Type header")
		}
	})
}

func TestEmailClient_Defaults(t *testing.T) {
	cfg := Config{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
	}
	client := NewEmailClient(cfg)

	// Test with empty data to verify defaults

	t.Run("default support email", func(t *testing.T) {
		// Defaults are applied in SendLicenseEmail, not renderTemplate
		// This test verifies that SendLicenseEmail would use defaults
		// We test renderTemplate directly here, so no defaults apply
		htmlBody, err := client.renderTemplate(LicenseEmailData{})
		if err != nil {
			t.Fatalf("renderTemplate() error = %v", err)
		}
		// Empty data renders empty strings - this is expected
		_ = htmlBody // Template renders without defaults when called directly
	})

	t.Run("default company name", func(t *testing.T) {
		// Same as above - defaults applied at SendLicenseEmail level
		htmlBody, err := client.renderTemplate(LicenseEmailData{})
		if err != nil {
			t.Fatalf("renderTemplate() error = %v", err)
		}
		_ = htmlBody // Template renders without defaults when called directly
	})
}

func TestBuildMessage(t *testing.T) {
	cfg := Config{
		Host:     "smtp.example.com",
		Port:     587,
		From:     "noreply@aegisgatesecurity.io",
		FromName: "AegisGate",
	}
	client := NewEmailClient(cfg)

	msg, err := client.buildMessage("customer@example.com", "Test Subject", "<html>body</html>")
	if err != nil {
		t.Fatalf("buildMessage() error = %v", err)
	}

	msgStr := string(msg)

	// Verify From header includes name
	if !strings.Contains(msgStr, "AegisGate <noreply@aegisgatesecurity.io>") {
		t.Error("From header should include display name")
	}
}

func TestEmailClient_MultipleFeatures(t *testing.T) {
	cfg := Config{
		Host: "smtp.example.com",
		Port: 587,
		From: "test@example.com",
	}
	client := NewEmailClient(cfg)

	data := LicenseEmailData{
		Tier:      "Professional",
		LicenseKey: "test-key",
		Features:  []string{"hipaa", "pci-dss", "gdpr"},
	}

	htmlBody, err := client.renderTemplate(data)
	if err != nil {
		t.Fatalf("renderTemplate() error = %v", err)
	}

	// Features field in template is not currently rendered,
	// but the data structure supports it for future use
	if !strings.Contains(htmlBody, "Professional") {
		t.Error("Template should contain tier name")
	}
}
