// SPDX-License-Identifier: Apache-2.0
// Test script for live email delivery

package main

import (
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/email"
)

func main() {
	// Proton Mail SMTP configuration
	cfg := email.DefaultProtonMailConfig(
		"license@aegisgatesecurity.io",
		"CMBJ3MY2JHVCC3PD",
		"AegisGate Security",
	)

	// Validate config
	if err := email.ValidateConfig(cfg); err != nil {
		fmt.Printf("❌ Config validation failed: %v\n", err)
		return
	}

	// Create email client
	client := email.NewEmailClient(cfg)

	// Generate a test license (just for the key format)
	licenseKey := "eyJwYXlsb2FkIjp7ImxpY2Vuc2VfaWQiOiJ0ZXN0LXVzZXItaWQiLCJ0aWVyIjoiZGV2ZWxvcGVyIiwiY3VzdG9tZXIiOiJUZXN0IFVzZXIiLCJpc3N1ZWRfYXQiOiIyMDI2LTA0LTI5VDE2OjQxOjAwWiIsImV4cGlyZXNfYXQiOiIyMDI2LTA1LTI5VDE2OjQxOjAwWiIsImZlYXR1cmVzIjpbInN0YXJ0ZXJfbW9kZSJdfQ=="

	// Email data
	data := email.LicenseEmailData{
		CustomerName: "Test Customer",
		Tier:         "Developer",
		LicenseKey:   licenseKey,
		IssuedAt:     time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700"),
		ExpiresAt:    time.Now().AddDate(0, 1, 0).Format("Mon, 02 Jan 2006 15:04:05 -0700"),
		Features:     []string{"starter_mode"},
		SupportEmail: "support@aegisgatesecurity.io",
		CompanyName:  "AegisGate Security, LLC",
		CompanyURL:   "https://aegisgatesecurity.io",
	}

	// Send to the sending address (self-test)
	fmt.Printf("📧 Sending test email to %s...\n", cfg.From)
	
	err := client.SendLicenseEmail(cfg.From, data)
	if err != nil {
		fmt.Printf("❌ Email send failed: %v\n", err)
		return
	}

	fmt.Println("✅ Test email sent successfully!")
	fmt.Println("   Check your inbox at license@aegisgatesecurity.io")
}
