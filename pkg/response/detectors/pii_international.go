// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - International PII Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/pii-international-id.js (24 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// =========================================================================

package detectors

// PIIInternationalPatterns defines international PII patterns for national IDs,
// passports, residence permits, and driver licenses.
// Lens parity: pii-international-id.js v0.1.1 (24 patterns).
var PIIInternationalPatterns = []PatternDef{
	{
		Name:        "pii_cpf_br",
		Severity:    SeverityCritical,
		Regex:       `\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`,
		Description: "Brazilian CPF number",
	},
	{
		Name:        "pii_aadhaar_in",
		Severity:    SeverityCritical,
		Regex:       `\d{4}[-\s]\d{4}[-\s]\d{4}`,
		Description: "Indian Aadhaar number (12 digits, XXXX-XXXX-XXXX)",
	},
	{
		Name:        "pii_nhs_uk",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:NHS|NHS\s+Number|National\s+Health\s+Service)\s*[:\#]?\s*(?:No\.?|Number)?\s*[:\#]?\s*\d{3}-\d{3}-\d{4}\b`,
		Description: "UK NHS number (requires NHS label)",
	},
	{
		Name:        "pii_tfn_au",
		Severity:    SeverityHigh,
		Regex:       `\b\d{3}\s\d{3}\s\d{3}\b`,
		Description: "Australian Tax File Number (9 digits, space-separated)",
	},
	{
		Name:        "pii_sin_ca",
		Severity:    SeverityHigh,
		Regex:       `\b[1-7]\d{2}\s\d{3}\s\d{3}\b`,
		Description: "Canadian SIN (9 digits, space-separated)",
	},
	{
		Name:        "pii_iban",
		Severity:    SeverityCritical,
		Regex:       `\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`,
		Description: "International Bank Account Number (IBAN)",
	},
	{
		Name:        "pii_bip39_seed",
		Severity:    SeverityCritical,
		Regex:       `\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b|\b(?:[a-z]{3,8}\s+){23}[a-z]{3,8}\b`,
		Description: "BIP39 cryptocurrency seed phrase (12 or 24 words)",
	},
	{
		Name:        "pii_passport_uk",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:UK|United\s+Kingdom)?\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b`,
		Description: "UK passport number (9 digits, requires label)",
	},
	{
		Name:        "pii_passport_eu",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:European\s+Union|EU)\s*Passport\s*(?:#|No\.?)?\s*([A-Z]{1,2}\d{6,8})\b`,
		Description: "EU passport number (requires label)",
	},
	{
		Name:        "pii_passport_ca",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:Canadian|Canada)\s*Passport\s*(?:#|No\.?)?\s*([A-Z]\d{8})\b`,
		Description: "Canadian passport number",
	},
	{
		Name:        "pii_passport_au",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:Australian|Australia)\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b`,
		Description: "Australian passport number",
	},
	{
		Name:        "pii_passport_de",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:German|Germany)\s*Passport\s*(?:#|No\.?)?\s*(?:([A-Z]\d{8})|(D\d{8}))\b`,
		Description: "German passport number",
	},
	{
		Name:        "pii_passport_fr",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:French|France)\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b`,
		Description: "French passport number",
	},
	{
		Name:        "pii_nid_de",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:German\s+Nationalseid|Personalausweis|PA)\s*[:\#]?\s*(\d{11})\b`,
		Description: "German national ID number",
	},
	{
		Name:        "pii_nid_fr",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:French\s+National\s+ID|Carte\s+Nationale|Carte\s+Nationale\s+Identite|CN)\s*[:\#]?\s*([A-Z]{1,5}\d{10})\b`,
		Description: "French national ID number",
	},
	{
		Name:        "pii_nid_es",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:Spanish\s+National\s+ID|DNI)\s*[:\#]?\s*(\d{8}[A-Z])\b`,
		Description: "Spanish DNI number",
	},
	{
		Name:        "pii_nid_it",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:Italian\s+National\s+ID|Codice\s+Fiscale|CF)\s*[:\#]?\s*([A-Z0-9]{16})\b`,
		Description: "Italian Codice Fiscale",
	},
	{
		Name:        "pii_nid_jp",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:Japanese\s+National\s+ID|My\s+Number|MyNumber)\s*[:\#]?\s*(\d{3}-\d{3}-\d{5,6})\b`,
		Description: "Japanese My Number national ID",
	},
	{
		Name:        "pii_residence_us",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:I-551|Green\s+Card|Resident\s+Permit)\s*([A-Z]?\d{9,11})\b`,
		Description: "US Permanent Resident Card (Green Card) number",
	},
	{
		Name:        "pii_residence_ca",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:Permanent\s+Resident|PR\s+Card|Canadians?\s+Permanent\s+Resident)\s*([A-Z]?\d{9,11})\b`,
		Description: "Canadian Permanent Resident Card number",
	},
	{
		Name:        "pii_residence_uk",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:Biometric\s+Residence\s+Permit|BRP)\s*([A-Z]?\d{9,11})\b`,
		Description: "UK Biometric Residence Permit (BRP) number",
	},
	{
		Name:        "pii_visa",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:Visa|visa)\s+(?:number|entry|entry\s+type)?\s*[:=]?\s*([A-Z0-9]{8,17})\b`,
		Description: "Visa number or entry type",
	},
	{
		Name:        "pii_driver_license_international",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:(?:Driver's\s+License|State\s+ID|Permis\s+conduire|Führerschein|Patente|Licencia|Permiso|Brevetto)\s*[:\#]?\s*[A-Z]?\d{5,15}|(?:Korti\s+ajamiso|Dokument\s+tożsamości)\s*[:\#]?\s*\d{5,15})\b`,
		Description: "International driver license (non-US formats)",
	},
	{
		Name:        "pii_ipv6",
		Severity:    SeverityLow,
		Regex:       `(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}`,
		Description: "IPv6 address",
	},
}

// CompiledPIIInternationalPatterns holds pre-compiled international PII regex patterns.
var CompiledPIIInternationalPatterns []compiledPattern

func init() {
	CompiledPIIInternationalPatterns = compilePatterns(PIIInternationalPatterns)
}

// DetectPIIInternational scans text for all international PII patterns and returns matches.
func DetectPIIInternational(text string) []Match {
	return detectWithPatterns(text, CompiledPIIInternationalPatterns, string(CategoryPIIInternational))
}
