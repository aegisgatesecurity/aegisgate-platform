// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - US Core PII Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/pii-us-core.js (15 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// RE2 does not support lookbehind/lookahead; patterns requiring those
// features have been rewritten or relaxed.
// =========================================================================

package detectors

// PIIUSCorePatterns defines US high-priority PII detection patterns.
// Lens parity: pii-us-core.js v0.2.0 (15 patterns).
var PIIUSCorePatterns = []PatternDef{
	{
		Name:        "pii_ssn",
		Severity:    SeverityCritical,
		Regex:       `\b\d{3}[-\s]\d{2}[-\s]\d{4}\b`,
		Description: "US Social Security Number (XXX-XX-XXXX or XXX XX XXXX)",
	},
	{
		Name:        "pii_email",
		Severity:    SeverityMedium,
		Regex:       `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}`,
		Description: "Email address",
	},
	{
		Name:        "pii_phone",
		Severity:    SeverityMedium,
		Regex:       `(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`,
		Description: "US phone number (10 digits with optional +1 prefix)",
	},
	{
		Name:        "pii_credit_card",
		Severity:    SeverityHigh,
		Regex:       `\b(?:\d{4}[ -]?){3}\d{1,7}\b|\b\d{13,19}\b`,
		Description: "Credit card number (13-19 digits with optional separators)",
	},
	{
		Name:        "pii_dob",
		Severity:    SeverityHigh,
		Regex:       `\b(?:(?:0?[1-9]|1[0-2])[/.\-](?:0?[1-9]|[12]\d|3[01])[/.\-](?:19|20)\d{2}|(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01]))\b`,
		Description: "Date of birth (MM/DD/YYYY, MM-DD-YYYY, or YYYY-MM-DD)",
	},
	{
		Name:        "pii_address",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b\d{1,6}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Place|Pl)\b\.?(?:\s+(?:Apt|Suite|Ste|#)\s*\d+)?`,
		Description: "US street address",
	},
	{
		Name:        "pii_driver_license",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:DL|D\.L\.|Driver(?:'s)?\s+License|License)\s*[:\#]?\s*(?:No\.?|Number)?\s*[:\#]?\s*[A-Z0-9]{5,15}\b`,
		Description: "US driver license number",
	},
	{
		Name:        "pii_passport",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:US|United\s+States\s+)?Passport\s*(?:#|No\.?)?\s*[A-Z]\d{8}\b`,
		Description: "US passport number (1 letter + 8 digits, requires label)",
	},
	{
		Name:        "pii_tax_id",
		Severity:    SeverityHigh,
		Regex:       `\b\d{2}-\d{7}\b`,
		Description: "US EIN (Employer Identification Number)",
	},
	{
		Name:        "pii_bank_account",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:Routing|Account|ABA)\s*(?:#|No\.?|Number)?\s*\d{4,17}\b`,
		Description: "Bank account or routing number (with label)",
	},
	{
		Name:        "pii_ip_address",
		Severity:    SeverityLow,
		Regex:       `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`,
		Description: "IPv4 address",
	},
	{
		Name:        "pii_mrn",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:MRN|Medical\s+Record\s+(?:Number|No\.?|#)|Patient\s+(?:ID|Number|No\.?|#))\b\s*[:=#]?\s*[A-Z0-9][A-Z0-9\-]{4,10}[A-Z0-9]\b`,
		Description: "Medical Record Number (requires label)",
	},
	{
		Name:        "pii_icd10_code",
		Severity:    SeverityMedium,
		Regex:       `\b[A-TV-Z][0-9][0-9AB]\.[0-9A-TV-Z]{1,4}\b`,
		Description: "ICD-10-CM diagnosis code",
	},
	{
		Name:        "pii_npi",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:NPI|National\s+Provider\s+(?:ID|Identifier|Number))\s*[:=#]?\s*[0-9]{10}\b`,
		Description: "National Provider Identifier (US healthcare)",
	},
	{
		Name:        "pii_ssn_last4",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:SSN|Social\s+Security)\s+(?:last|final)\s+(?:4|four)\s*(?:[:=#]|is|was|are|of|equals)?\s*[0-9]{4}\b`,
		Description: "SSN last-4 digits (requires keyword context)",
	},
	// CPT (Current Procedural Terminology) - Healthcare billing codes
	{
		Name:        "pii_cpt_code",
		Severity:    SeverityMedium,
		Regex:       `\b[0-9]{5}\b`,
		Description: "CPT medical billing code (5-digit numeric)",
	},
	{
		Name:        "pii_cpt_code_label",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:CPT|procedure\s+code)\s*[:=]?\s*[0-9]{5}\b`,
		Description: "CPT code with label",
	},
	// HCPCS (Healthcare Common Procedure Coding System) - Level II codes
	{
		Name:        "pii_hcpcs_level2",
		Severity:    SeverityMedium,
		Regex:       `\b[A-Z][0-9]{4}\b`,
		Description: "HCPCS Level II code (1 letter + 4 digits)",
	},
	{
		Name:        "pii_hcpcs_level2_label",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:HCPCS|healthcare\s+procedure\s+code)\s*[:=]?\s*[A-Z][0-9]{4}\b`,
		Description: "HCPCS code with label",
	},
	// HCPCS Level III (local codes, less common but still valid)
	{
		Name:        "pii_hcpcs_level3",
		Severity:    SeverityLow,
		Regex:       `\b[A-Z][0-9]{4}[A-Z]\b`,
		Description: "HCPCS Level III code (1 letter + 4 digits + 1 letter)",
	},
	// CPT Category II (performance measurement, 4 digits + F)
	{
		Name:        "pii_cpt_cat2",
		Severity:    SeverityLow,
		Regex:       `\b[0-9]{4}F\b`,
		Description: "CPT Category II code (4 digits + F suffix)",
	},
	// CPT Category III (emerging technology, 4 digits + T)
	{
		Name:        "pii_cpt_cat3",
		Severity:    SeverityLow,
		Regex:       `\b[0-9]{4}T\b`,
		Description: "CPT Category III code (4 digits + T suffix)",
	},
	// Common CPT ranges for specific services (high-value fraud indicators)
	{
		Name:        "pii_cpt_evaluation",
		Severity:    SeverityMedium,
		Regex:       `\b9(?:920[34]|921[1-5]|930[0-5]|940[1-4])\b`,
		Description: "CPT evaluation/management codes (office visits)",
	},
	{
		Name:        "pii_cpt_lab",
		Severity:    SeverityMedium,
		Regex:       `\b8(?:0053|1000|2000|3000|4000|5000|6000|7000|8000)\b`,
		Description: "CPT laboratory/pathology codes",
	},
	{
		Name:        "pii_cpt_radiology",
		Severity:    SeverityMedium,
		Regex:       `\b7(?:0000|1000|2000|3000|4000|5000|6000|7000|8000)\b`,
		Description: "CPT radiology codes (X-ray, CT, MRI)",
	},
	{
		Name:        "pii_cpt_surgery",
		Severity:    SeverityHigh,
		Regex:       `\b(?:10004|20000|30000|40000|50000|60000)\b`,
		Description: "CPT surgery codes (high-value procedures)",
	},
}

// CompiledPIIUSCorePatterns holds pre-compiled US core PII regex patterns.
var CompiledPIIUSCorePatterns []compiledPattern

func init() {
	CompiledPIIUSCorePatterns = compilePatterns(PIIUSCorePatterns)
}

// DetectPIIUSCore scans text for all US core PII patterns and returns matches.
func DetectPIIUSCore(text string) []Match {
	return detectWithPatterns(text, CompiledPIIUSCorePatterns, string(CategoryPIIUSCore))
}
