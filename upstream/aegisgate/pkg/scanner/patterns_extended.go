package scanner

import "regexp"

// AdditionalCategories adds new category constants
const (
	CategoryHealthcare Category = "Healthcare"
	CategoryCloud      Category = "Cloud"
	CategoryDocument   Category = "Document"
)

// AdditionalPatterns returns extended detection patterns
// These can be merged with DefaultPatterns() for enhanced coverage
func AdditionalPatterns() []*Pattern {
	return []*Pattern{
		// CLOUD PROVIDER TOKENS
		{
			Name:        "DiscordWebhook",
			Regex:       regexp.MustCompile(`https://discord\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_-]{68}`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "Discord webhook URL detected",
		},
		{
			Name:        "GoogleOAuthClientID",
			Regex:       regexp.MustCompile(`\b[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "Google OAuth client ID detected",
		},
		{
			Name:        "SendGridAPIKey",
			Regex:       regexp.MustCompile(`\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b`),
			Severity:    Critical,
			Category:    CategoryCredential,
			Description: "SendGrid API key detected",
		},
		{
			Name:        "TwilioAccountSID",
			Regex:       regexp.MustCompile(`\bAC[a-f0-9]{32}\b`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "Twilio Account SID detected",
		},
		{
			Name:        "SquareAccessToken",
			Regex:       regexp.MustCompile(`\bsq0atp-[a-zA-Z0-9_-]{22}\b`),
			Severity:    Critical,
			Category:    CategoryCredential,
			Description: "Square access token detected",
		},
		{
			Name:        "PayPalBraintree",
			Regex:       regexp.MustCompile(`\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b`),
			Severity:    Critical,
			Category:    CategoryCredential,
			Description: "PayPal/Braintree access token detected",
		},
		{
			Name:        "KubernetesServiceToken",
			Regex:       regexp.MustCompile(`eyJhbGciOiJSUzI1NiIsImtpZCI6I[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
			Severity:    Critical,
			Category:    CategoryCredential,
			Description: "Kubernetes service account token detected",
		},

		// HEALTHCARE DATA
		{
			Name:        "MedicalRecordNumber",
			Regex:       regexp.MustCompile(`(?i)(?:mrn|medical\s*record)\s*(?:number|no|#)?\s*[:=]?\s*\b[0-9]{6,10}\b`),
			Severity:    High,
			Category:    CategoryHealthcare,
			Description: "Medical record number detected",
		},
		{
			Name:        "MedicareNumber",
			Regex:       regexp.MustCompile(`\b[0-9]{3}-?[0-9]{2}-?[0-9]{4}\s*[A-Z]?\b`),
			Severity:    Critical,
			Category:    CategoryHealthcare,
			Description: "Medicare/Medicaid number detected",
		},
		{
			Name:        "ICD10Code",
			Regex:       regexp.MustCompile(`\b[A-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?\b`),
			Severity:    Info,
			Category:    CategoryHealthcare,
			Description: "ICD-10 diagnosis code detected",
		},

		// DOCUMENT IDENTIFIERS
		{
			Name:        "USTaxID",
			Regex:       regexp.MustCompile(`(?i)(?:ein|tax\s*id)\s*(?:number|no|#)?\s*[:=]?\s*\b[0-9]{2}-?[0-9]{7}\b`),
			Severity:    High,
			Category:    CategoryDocument,
			Description: "US Employer ID (EIN) detected",
		},
		{
			Name:        "VehicleVIN",
			Regex:       regexp.MustCompile(`\b[A-HJ-NPR-Z0-9]{17}\b`),
			Severity:    Medium,
			Category:    CategoryDocument,
			Description: "Vehicle VIN detected",
		},
		{
			Name:        "LicensePlate",
			Regex:       regexp.MustCompile(`(?i)(?:license\s*plate|plate\s*number)\s*[:=]?\s*\b[A-Z0-9]{3,8}\b`),
			Severity:    Low,
			Category:    CategoryDocument,
			Description: "License plate detected",
		},

		// CLOUD PROVIDER IDs
		{
			Name:        "AWSAccountID",
			Regex:       regexp.MustCompile(`\b[0-9]{12}\b`),
			Severity:    Low,
			Category:    CategoryCloud,
			Description: "AWS Account ID detected",
		},
		{
			Name:        "AzureSubscriptionID",
			Regex:       regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
			Severity:    Medium,
			Category:    CategoryCloud,
			Description: "Azure Subscription ID detected",
		},
		{
			Name:        "GCPProjectID",
			Regex:       regexp.MustCompile(`(?i)(?:gcp|google\s*cloud)\s*(?:project)?\s*[:=]?\s*\b[a-z][a-z0-9-]{4,28}[a-z0-9]\b`),
			Severity:    Low,
			Category:    CategoryCloud,
			Description: "GCP Project ID detected",
		},

		// NETWORK
		{
			Name:        "IPv6Address",
			Regex:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
			Severity:    Low,
			Category:    CategoryNetwork,
			Description: "IPv6 address detected",
		},
		{
			Name:        "MACAddress",
			Regex:       regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b`),
			Severity:    Low,
			Category:    CategoryNetwork,
			Description: "MAC address detected",
		},
	}
}

// AllPatterns returns combined default and additional patterns
func AllPatterns() []*Pattern {
	return append(DefaultPatterns(), AdditionalPatterns()...)
}
