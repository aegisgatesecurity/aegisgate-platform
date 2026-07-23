// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - US Extended PII Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/pii-us-extended.js (13 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// RE2 does not support lookbehind/lookahead; patterns requiring those
// features have been relaxed (removed lookarounds).
// =========================================================================

package detectors

// PIIUSExtendedPatterns defines extended US and international PII patterns.
// Lens parity: pii-us-extended.js v0.2.0 (13 patterns).
var PIIUSExtendedPatterns = []PatternDef{
	{
		Name:        "pii_credit_card_loose",
		Severity:    SeverityHigh,
		Regex:       `\b\d{12,19}\b`,
		Description: "Credit card number (loose: 12-19 digits, use Luhn validation)",
	},
	{
		Name:        "pii_email_intl",
		Severity:    SeverityMedium,
		Regex:       `[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.[\p{L}]{2,24}`,
		Description: "International email (CJK/Hangul/Kana support)",
	},
	{
		Name:        "pii_phone_intl_loose",
		Severity:    SeverityMedium,
		Regex:       `\+?\d[\d\s\-()]{6,12}\d`,
		Description: "International phone number (loose: digits with separators)",
	},
	{
		Name:        "pii_phone_intl_strict",
		Severity:    SeverityMedium,
		Regex:       `\+?\d{1,3}[\s\-.()]{1,2}\(?\d{2,4}\)?[\s\-.()]{0,2}\d{3,4}[\s\-.()]{0,2}\d{3,4}`,
		Description: "International phone number (strict: formatted with separators)",
	},
	{
		Name:        "pii_passport_generic",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:passport|id|license|certificate)\s*[:\#]?\s*[A-Z0-9]{6,9}\b`,
		Description: "Generic passport/ID number (6-9 alphanumeric, requires label)",
	},
	{
		Name:        "pii_id_generic_alphanumeric",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:id|code|number|ref|license|passport|certificate|serial|account)\s*[:\#]?\s*[A-Z0-9]{4,15}\b`,
		Description: "Generic alphanumeric ID (4-15 chars, requires label)",
	},
	{
		Name:        "pii_ssn_fr",
		Severity:    SeverityCritical,
		Regex:       `\b[12]\d{2}\.\d{2}\.\d{2}\.\d{3}\.\d{2}\b|\b\d{3}\.\d{4}\.\d{4}\.\d{2}\b`,
		Description: "French INSEE SSN number",
	},
	{
		Name:        "pii_ssn_ru",
		Severity:    SeverityCritical,
		Regex:       `\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2,3}\b`,
		Description: "Russian SNILS number",
	},
	{
		Name:        "pii_tax_id_ch",
		Severity:    SeverityHigh,
		Regex:       `\bCHE-\d{3}\.\d{3}\.\d{3}\b`,
		Description: "Swiss UID (CHE-XXX.XXX.XXX)",
	},
	{
		Name:        "pii_letter_only_id",
		Severity:    SeverityHigh,
		Regex:       `\b[A-Z]{8,12}\b`,
		Description: "Pure-letter 8-12 char uppercase ID (requires context)",
	},
	{
		Name:        "pii_id_multisegment",
		Severity:    SeverityHigh,
		Regex:       `\b[A-Z][A-Z0-9]{1,7}[-.][A-Z0-9]{1,8}(?:[-.][A-Z0-9]{1,8}){1,3}\b`,
		Description: "Multi-segment ID code (e.g., SHERZ.790015.S9.027)",
	},
	{
		Name:        "pii_street_intl",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:Bulevardul|Bd\.|Intrarea|Strada|Str\.|Aleea|Piața|Calea)\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+Nr\.?\s+\d+\b`,
		Description: "International street address (Romanian, etc.)",
	},
	{
		Name:        "pii_ip_address_v6",
		Severity:    SeverityLow,
		Regex:       `(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}`,
		Description: "IPv6 address",
	},
}

// CompiledPIIUSExtendedPatterns holds pre-compiled US extended PII regex patterns.
var CompiledPIIUSExtendedPatterns []compiledPattern

func init() {
	CompiledPIIUSExtendedPatterns = compilePatterns(PIIUSExtendedPatterns)
}

// DetectPIIUSExtended scans text for all US extended PII patterns and returns matches.
func DetectPIIUSExtended(text string) []Match {
	return detectWithPatterns(text, CompiledPIIUSExtendedPatterns, string(CategoryPIIUSExtended))
}
