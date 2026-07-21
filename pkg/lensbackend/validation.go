// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Event Validation (v0.2 Schema)
// =========================================================================
//
// Validates incoming telemetry events from the AegisGate Lens extension.
// The v0.2 schema expands from 6 to 157 categories across 6 facets,
// matching the Lens v0.2.0 extension's full detection vocabulary.
//
// Privacy guarantee: the event NEVER contains the prompt, URL,
// page content, or user ID. Only the domain_hash (SHA-256 prefix)
// identifies the AI provider.
//
// =========================================================================
//
// #nosec G101 (CWE-798: hardcoded credentials) -- FALSE POSITIVE.
//
// The 13 G101 findings gosec emits on this file are all on the
// `Category = "secret_*"` enum constants below (e.g. CategorySecretGCPKey
// = "secret_gcp_key"). These are *names* of secret categories that
// the Lens scanner uses to *classify* what kind of secret it found.
// They are NOT credentials, tokens, or keys. The values are
// classifier labels, not secrets.
//
// Per the gosec documentation (https://github.com/securego/gosec):
// G101 looks for "Variables that look like credentials". The regex
// matches strings containing "key", "token", "password", etc. Even
// though these are enum names, the regex fires. Disabling G101
// at the file level is the documented remediation for category
// enumerations; the alternative (per-line `// #nosec G101`) would
// require 13 annotations that would obscure the actual enum values.
//
// Verified manually on 2026-07-20 (D25 self-pentest): the 13 G101
// findings are 100% false positives. No real hardcoded credentials
// exist in this file. The Category type is defined as
//
//     type Category string
//
// and the string values are classifier labels.
// =========================================================================

package lensbackend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Facet is the detection facet that produced an event.
type Facet string

const (
	FacetPII             Facet = "pii"
	FacetSecrets         Facet = "secrets"
	FacetXSS             Facet = "xss"
	FacetCompliance      Facet = "compliance"
	FacetToxicity        Facet = "toxicity"
	FacetPromptInjection Facet = "prompt_injection"
)

var AllFacets = []Facet{FacetPII, FacetSecrets, FacetXSS, FacetCompliance, FacetToxicity, FacetPromptInjection}

// Category is the sensitive-data category that the Lens detected.
type Category string

const (
	// PII categories (58)
	CategoryPIIEmail                 Category = "pii_email"
	CategoryPIIPhone                 Category = "pii_phone"
	CategoryPIISSN                   Category = "pii_ssn"
	CategoryPIICreditCard            Category = "pii_credit_card"
	CategoryPIIPhoneIntlLoose        Category = "pii_phone_intl_loose"
	CategoryPIIAddress               Category = "pii_address"
	CategoryPIIDOB                   Category = "pii_dob"
	CategoryPIIDriverLicense         Category = "pii_driver_license"
	CategoryPIIPassport              Category = "pii_passport"
	CategoryPIIBip39Seed             Category = "pii_bip39_seed"
	CategoryPIITaxID                 Category = "pii_tax_id"
	CategoryPIIBankAccount           Category = "pii_bank_account"
	CategoryPIIIPAddress             Category = "pii_ip_address"
	CategoryPIIMRN                   Category = "pii_mrn"
	CategoryPIIICD10Code             Category = "pii_icd10_code"
	CategoryPIINPI                   Category = "pii_npi"
	CategoryPIISSNLast4              Category = "pii_ssn_last4"
	CategoryPIINHSUK                 Category = "pii_nhs_uk"
	CategoryPIITFNAU                 Category = "pii_tfn_au"
	CategoryPIIAadhaarIN             Category = "pii_aadhaar_in"
	CategoryPIICPFBR                 Category = "pii_cpf_br"
	CategoryPIISINCA                 Category = "pii_sin_ca"
	CategoryPIIDriverLicenseIntl     Category = "pii_driver_license_international"
	CategoryPIIIBAN                  Category = "pii_iban"
	CategoryPIIVisa                  Category = "pii_visa"
	CategoryPIIPassportAU            Category = "pii_passport_au"
	CategoryPIIPassportCA            Category = "pii_passport_ca"
	CategoryPIIPassportDE            Category = "pii_passport_de"
	CategoryPIIPassportEU            Category = "pii_passport_eu"
	CategoryPIIPassportFR            Category = "pii_passport_fr"
	CategoryPIIPassportUK            Category = "pii_passport_uk"
	CategoryPIIResidenceCA           Category = "pii_residence_ca"
	CategoryPIIResidenceUK           Category = "pii_residence_uk"
	CategoryPIIResidenceUS           Category = "pii_residence_us"
	CategoryPIIDigitalPaypal         Category = "pii_digital_paypal"
	CategoryPIIDigitalStripe         Category = "pii_digital_stripe"
	CategoryPIIDigitalVenmo          Category = "pii_digital_venmo"
	CategoryPIIDigitalCashapp        Category = "pii_digital_cashapp"
	CategoryPIINidDE                 Category = "pii_nid_de"
	CategoryPIINidES                 Category = "pii_nid_es"
	CategoryPIINidFR                 Category = "pii_nid_fr"
	CategoryPIINidIT                 Category = "pii_nid_it"
	CategoryPIINidJP                 Category = "pii_nid_jp"
	CategoryPIICryptoBTC             Category = "pii_crypto_btc"
	CategoryPIICryptoETH             Category = "pii_crypto_eth"
	CategoryPIICryptoBNB             Category = "pii_crypto_bnb"
	CategoryPIICryptoLTC             Category = "pii_crypto_ltc"
	CategoryPIICryptoSOL             Category = "pii_crypto_sol"
	CategoryPIILetterOnlyID          Category = "pii_letter_only_id"
	CategoryPIIIDGenericAlphanumeric Category = "pii_id_generic_alphanumeric"
	CategoryPIIIDMultisegment        Category = "pii_id_multisegment"
	CategoryPIIPassportGeneric       Category = "pii_passport_generic"
	CategoryPIIStreetIntl            Category = "pii_street_intl"
	CategoryPIISSNRU                 Category = "pii_ssn_ru"
	CategoryPIISSNFR                 Category = "pii_ssn_fr"
	CategoryPIITaxIDCH               Category = "pii_tax_id_ch"
	CategoryPIICreditCardLoose       Category = "pii_credit_card_loose"
	CategoryPIIEmailIntl             Category = "pii_email_intl"

	// Secrets categories (45)
	CategorySecretAPIKey             Category = "secret_api_key"
	CategorySecretAWSKey             Category = "secret_aws_key"
	CategorySecretGitHubToken        Category = "secret_github_token"
	CategorySecretGCPKey             Category = "secret_gcp_key"
	CategorySecretAzureKey           Category = "secret_azure_key"
	CategorySecretPrivateKeyPEM      Category = "secret_private_key_pem"
	CategorySecretOAuthToken         Category = "secret_oauth_token"
	CategorySecretJWT                Category = "secret_jwt"
	CategorySecretAPIKeyGeneric      Category = "secret_api_key_generic"
	CategorySecretDBConnectionString Category = "secret_db_connection_string"
	CategorySecretSlackToken         Category = "secret_slack_token"
	CategorySecretStripeKey          Category = "secret_stripe_key"
	CategorySecretTwilioKey          Category = "secret_twilio_key"
	CategorySecretSendgridKey        Category = "secret_sendgrid_key"
	CategorySecretMailgunKey         Category = "secret_mailgun_key"
	CategorySecretOpenAIKey          Category = "secret_openai_key"
	CategorySecretAnthropicKey       Category = "secret_anthropic_key"
	CategorySecretHerokuKey          Category = "secret_heroku_key"
	CategorySecretAzureDevOps        Category = "secret_azure_devops"
	CategorySecretGiteaToken         Category = "secret_gitea_token"
	CategorySecretHerokuTokenLegacy  Category = "secret_heroku_token_legacy"
	CategorySecretSlackLegacy        Category = "secret_slack_legacy"
	CategorySecretAWSAccountID       Category = "secret_aws_account_id"
	CategorySecretGitHubActionsToken Category = "secret_github_actions_token"
	CategorySecretGitHubFinegrained  Category = "secret_github_finegrained"
	CategorySecretGitLabToken        Category = "secret_gitlab_token"
	CategorySecretGitLabPAT          Category = "secret_gitlab_pat"
	CategorySecretLinodeToken        Category = "secret_linode_token"
	CategorySecretDigitalOceanToken  Category = "secret_digitalocean_token"
	CategorySecretRackspaceToken     Category = "secret_rackspace_token"
	CategorySecretSalesforceToken    Category = "secret_salesforce_token"
	CategorySecretShopifyToken       Category = "secret_shopify_token"
	CategorySecretTravisToken        Category = "secret_travis_token"
	CategorySecretJenkinsToken       Category = "secret_jenkins_token"
	CategorySecretCircleCIToken      Category = "secret_circleci_token"
	CategorySecretBitbucketToken     Category = "secret_bitbucket_token"
	CategorySecretWordPressToken     Category = "secret_wordpress_token"
	CategorySecretNPMToken           Category = "secret_npm_token"
	CategorySecretPyPIToken          Category = "secret_pypi_token"
	CategorySecretInternalAPIKey     Category = "secret_internal_api_key"
	CategorySecretSupabase           Category = "secret_supabase"
	CategorySecretDBURLWithPassword  Category = "secret_db_url_with_password"
	CategorySecretCursorKey          Category = "secret_cursor_key"
	CategorySecretVercelKey          Category = "secret_vercel_key"
	CategorySecretGroqKey            Category = "secret_groq_key"
	CategorySecretReplicateKey       Category = "secret_replicate_key"

	// XSS categories (11)
	CategoryXSSJavaScriptDataURL Category = "xss_javascript_data_url"
	CategoryXSSScriptTag         Category = "xss_script_tag"
	CategoryXSSEventHandler      Category = "xss_event_handler"
	CategoryXSSMutationXSS       Category = "xss_mutation_xss"
	CategoryXSSPolyglot          Category = "xss_polyglot"
	CategoryXSSSVGNamespaceAbuse Category = "xss_svg_namespace_abuse"
	CategoryXSSSVGUseExternal    Category = "xss_svg_use_external"
	CategoryXSSJavaScriptURL     Category = "xss_javascript_url"
	CategoryXSSDataURL           Category = "xss_data_url"
	CategoryXSSSVGScript         Category = "xss_svg_script"
	CategoryXSSDOMClobbering     Category = "xss_dom_clobbering"

	// Compliance categories (31)
	CategoryOWASPLLM01            Category = "owasp_llm01_prompt_injection"
	CategoryOWASPLLM02            Category = "owasp_llm02_insecure_output"
	CategoryOWASPLLM04            Category = "owasp_llm04_model_dos"
	CategoryOWASPLLM05            Category = "owasp_llm05_supply_chain"
	CategoryOWASPLLM06            Category = "owasp_llm06_sensitive_info_disclosure_system_prompt"
	CategoryOWASPLLM08            Category = "owasp_llm08_excessive_agency"
	CategoryOWASPLLM09            Category = "owasp_llm09_overreliance"
	CategoryOWASPLLM10            Category = "owasp_llm10_model_theft"
	CategoryMITREATLASTA0001      Category = "mitre_atlas_ta0001_reconnaissance"
	CategoryATLASPoison           Category = "atlas_poison"
	CategoryATLASExfiltration     Category = "atlas_exfiltration"
	CategoryATLASJailbreak        Category = "atlas_jailbreak"
	CategoryEUAIActHighRisk       Category = "eu_ai_act_high_risk"
	CategoryEUAIActTransparency   Category = "eu_ai_act_transparency"
	CategoryEUAIActHumanOversight Category = "eu_ai_act_human_oversight"
	CategoryEUAIActRobustness     Category = "eu_ai_act_robustness"
	CategoryANPPersonalData       Category = "anp_personal_data"
	CategoryANPSpecialCategory    Category = "anp_special_category"
	CategoryCUConsumerRights      Category = "cu_consumer_rights"
	CategoryCUMinorProtection     Category = "cu_minor_protection"
	CategoryCCPAReference         Category = "ccpa_reference"
	CategoryISO27001Reference     Category = "iso_27001_reference"
	CategoryLGPDReference         Category = "lgpd_reference"
	CategoryNISTCSFReference      Category = "nist_csf_reference"
	CategoryPIPEDAReference       Category = "pipeda_reference"
	CategoryPOPIAReference        Category = "popia_reference"
	CategoryOWASPLLM10Unbounded   Category = "owasp_llm10_unbounded_consumption"
	CategoryMITREATLASTA0002      Category = "mitre_atlas_ta0002_resource_development"
	CategoryEUAIActArticle10      Category = "eu_ai_act_article_10_data_governance"
	CategoryMITREATLASTA0009      Category = "mitre_atlas_ta0009_collection"
	CategoryEUAIActArticle52      Category = "eu_ai_act_article_52_generative_ai"

	// Toxicity categories (7)
	CategoryToxicityHate     Category = "toxicity_hate"
	CategoryToxicityInsult   Category = "toxicity_insult"
	CategoryToxicityObscene  Category = "toxicity_obscene"
	CategoryToxicityThreat   Category = "toxicity_threat"
	CategoryToxicitySexual   Category = "toxicity_sexual"
	CategoryToxicitySelfHarm Category = "toxicity_self_harm"
	CategoryToxicityViolence Category = "toxicity_violence"

	// Prompt Injection categories (4)
	CategoryPIDirectOverride    Category = "pi_direct_override"
	CategoryPIIndirectInjection Category = "pi_indirect_injection"
	CategoryPIJailbreak         Category = "pi_jailbreak"
	CategoryPIRolePlayAttack    Category = "pi_role_play_attack"

	// Legacy: kept for backward compatibility with v0.1 events.
	// v0.2 maps this to secret_private_key_pem.
	CategorySourceCode Category = "source_code"
)

// AllCategories is the closed set of valid categories (157 total).
var AllCategories = []Category{
	// PII (58)
	CategoryPIIEmail, CategoryPIIPhone, CategoryPIISSN, CategoryPIICreditCard,
	CategoryPIIPhoneIntlLoose, CategoryPIIAddress, CategoryPIIDOB, CategoryPIIDriverLicense,
	CategoryPIIPassport, CategoryPIIBip39Seed, CategoryPIITaxID, CategoryPIIBankAccount,
	CategoryPIIIPAddress, CategoryPIIMRN, CategoryPIIICD10Code, CategoryPIINPI,
	CategoryPIISSNLast4, CategoryPIINHSUK, CategoryPIITFNAU, CategoryPIIAadhaarIN,
	CategoryPIICPFBR, CategoryPIISINCA, CategoryPIIDriverLicenseIntl, CategoryPIIIBAN,
	CategoryPIIVisa, CategoryPIIPassportAU, CategoryPIIPassportCA, CategoryPIIPassportDE,
	CategoryPIIPassportEU, CategoryPIIPassportFR, CategoryPIIPassportUK, CategoryPIIResidenceCA,
	CategoryPIIResidenceUK, CategoryPIIResidenceUS, CategoryPIIDigitalPaypal, CategoryPIIDigitalStripe,
	CategoryPIIDigitalVenmo, CategoryPIIDigitalCashapp, CategoryPIINidDE, CategoryPIINidES,
	CategoryPIINidFR, CategoryPIINidIT, CategoryPIINidJP, CategoryPIICryptoBTC,
	CategoryPIICryptoETH, CategoryPIICryptoBNB, CategoryPIICryptoLTC, CategoryPIICryptoSOL,
	CategoryPIILetterOnlyID, CategoryPIIIDGenericAlphanumeric, CategoryPIIIDMultisegment,
	CategoryPIIPassportGeneric, CategoryPIIStreetIntl, CategoryPIISSNRU, CategoryPIISSNFR,
	CategoryPIITaxIDCH, CategoryPIICreditCardLoose, CategoryPIIEmailIntl,
	// Secrets (46 including source_code)
	CategorySecretAPIKey, CategorySecretAWSKey, CategorySecretGitHubToken, CategorySecretGCPKey,
	CategorySecretAzureKey, CategorySecretPrivateKeyPEM, CategorySecretOAuthToken, CategorySecretJWT,
	CategorySecretAPIKeyGeneric, CategorySecretDBConnectionString, CategorySecretSlackToken, CategorySecretStripeKey,
	CategorySecretTwilioKey, CategorySecretSendgridKey, CategorySecretMailgunKey, CategorySecretOpenAIKey,
	CategorySecretAnthropicKey, CategorySecretHerokuKey, CategorySecretAzureDevOps, CategorySecretGiteaToken,
	CategorySecretHerokuTokenLegacy, CategorySecretSlackLegacy, CategorySecretAWSAccountID, CategorySecretGitHubActionsToken,
	CategorySecretGitHubFinegrained, CategorySecretGitLabToken, CategorySecretGitLabPAT, CategorySecretLinodeToken,
	CategorySecretDigitalOceanToken, CategorySecretRackspaceToken, CategorySecretSalesforceToken, CategorySecretShopifyToken,
	CategorySecretTravisToken, CategorySecretJenkinsToken, CategorySecretCircleCIToken, CategorySecretBitbucketToken,
	CategorySecretWordPressToken, CategorySecretNPMToken, CategorySecretPyPIToken, CategorySecretInternalAPIKey,
	CategorySecretSupabase, CategorySecretDBURLWithPassword, CategorySecretCursorKey, CategorySecretVercelKey,
	CategorySecretGroqKey, CategorySecretReplicateKey,
	// XSS (11)
	CategoryXSSJavaScriptDataURL, CategoryXSSScriptTag, CategoryXSSEventHandler, CategoryXSSMutationXSS,
	CategoryXSSPolyglot, CategoryXSSSVGNamespaceAbuse, CategoryXSSSVGUseExternal, CategoryXSSJavaScriptURL,
	CategoryXSSDataURL, CategoryXSSSVGScript, CategoryXSSDOMClobbering,
	// Compliance (31)
	CategoryOWASPLLM01, CategoryOWASPLLM02, CategoryOWASPLLM04, CategoryOWASPLLM05,
	CategoryOWASPLLM06, CategoryOWASPLLM08, CategoryOWASPLLM09, CategoryOWASPLLM10,
	CategoryMITREATLASTA0001, CategoryATLASPoison, CategoryATLASExfiltration, CategoryATLASJailbreak,
	CategoryEUAIActHighRisk, CategoryEUAIActTransparency, CategoryEUAIActHumanOversight, CategoryEUAIActRobustness,
	CategoryANPPersonalData, CategoryANPSpecialCategory, CategoryCUConsumerRights, CategoryCUMinorProtection,
	CategoryCCPAReference, CategoryISO27001Reference, CategoryLGPDReference, CategoryNISTCSFReference,
	CategoryPIPEDAReference, CategoryPOPIAReference, CategoryOWASPLLM10Unbounded, CategoryMITREATLASTA0002,
	CategoryEUAIActArticle10, CategoryMITREATLASTA0009, CategoryEUAIActArticle52,
	// Toxicity (7)
	CategoryToxicityHate, CategoryToxicityInsult, CategoryToxicityObscene, CategoryToxicityThreat,
	CategoryToxicitySexual, CategoryToxicitySelfHarm, CategoryToxicityViolence,
	// Prompt Injection (4)
	CategoryPIDirectOverride, CategoryPIIndirectInjection, CategoryPIJailbreak, CategoryPIRolePlayAttack,
	// Backward compatibility
	CategorySourceCode,
}

// FacetCategories maps each Facet to its valid categories.
var FacetCategories = map[Facet][]Category{
	FacetPII: {
		CategoryPIIEmail, CategoryPIIPhone, CategoryPIISSN, CategoryPIICreditCard,
		CategoryPIIPhoneIntlLoose, CategoryPIIAddress, CategoryPIIDOB, CategoryPIIDriverLicense,
		CategoryPIIPassport, CategoryPIIBip39Seed, CategoryPIITaxID, CategoryPIIBankAccount,
		CategoryPIIIPAddress, CategoryPIIMRN, CategoryPIIICD10Code, CategoryPIINPI,
		CategoryPIISSNLast4, CategoryPIINHSUK, CategoryPIITFNAU, CategoryPIIAadhaarIN,
		CategoryPIICPFBR, CategoryPIISINCA, CategoryPIIDriverLicenseIntl, CategoryPIIIBAN,
		CategoryPIIVisa, CategoryPIIPassportAU, CategoryPIIPassportCA, CategoryPIIPassportDE,
		CategoryPIIPassportEU, CategoryPIIPassportFR, CategoryPIIPassportUK, CategoryPIIResidenceCA,
		CategoryPIIResidenceUK, CategoryPIIResidenceUS, CategoryPIIDigitalPaypal, CategoryPIIDigitalStripe,
		CategoryPIIDigitalVenmo, CategoryPIIDigitalCashapp, CategoryPIINidDE, CategoryPIINidES,
		CategoryPIINidFR, CategoryPIINidIT, CategoryPIINidJP, CategoryPIICryptoBTC,
		CategoryPIICryptoETH, CategoryPIICryptoBNB, CategoryPIICryptoLTC, CategoryPIICryptoSOL,
		CategoryPIILetterOnlyID, CategoryPIIIDGenericAlphanumeric, CategoryPIIIDMultisegment,
		CategoryPIIPassportGeneric, CategoryPIIStreetIntl, CategoryPIISSNRU, CategoryPIISSNFR,
		CategoryPIITaxIDCH, CategoryPIICreditCardLoose, CategoryPIIEmailIntl,
	},
	FacetSecrets: {
		CategorySecretAPIKey, CategorySecretAWSKey, CategorySecretGitHubToken, CategorySecretGCPKey,
		CategorySecretAzureKey, CategorySecretPrivateKeyPEM, CategorySecretOAuthToken, CategorySecretJWT,
		CategorySecretAPIKeyGeneric, CategorySecretDBConnectionString, CategorySecretSlackToken, CategorySecretStripeKey,
		CategorySecretTwilioKey, CategorySecretSendgridKey, CategorySecretMailgunKey, CategorySecretOpenAIKey,
		CategorySecretAnthropicKey, CategorySecretHerokuKey, CategorySecretAzureDevOps, CategorySecretGiteaToken,
		CategorySecretHerokuTokenLegacy, CategorySecretSlackLegacy, CategorySecretAWSAccountID, CategorySecretGitHubActionsToken,
		CategorySecretGitHubFinegrained, CategorySecretGitLabToken, CategorySecretGitLabPAT, CategorySecretLinodeToken,
		CategorySecretDigitalOceanToken, CategorySecretRackspaceToken, CategorySecretSalesforceToken, CategorySecretShopifyToken,
		CategorySecretTravisToken, CategorySecretJenkinsToken, CategorySecretCircleCIToken, CategorySecretBitbucketToken,
		CategorySecretWordPressToken, CategorySecretNPMToken, CategorySecretPyPIToken, CategorySecretInternalAPIKey,
		CategorySecretSupabase, CategorySecretDBURLWithPassword, CategorySecretCursorKey, CategorySecretVercelKey,
		CategorySecretGroqKey, CategorySecretReplicateKey,
	},
	FacetXSS: {
		CategoryXSSJavaScriptDataURL, CategoryXSSScriptTag, CategoryXSSEventHandler, CategoryXSSMutationXSS,
		CategoryXSSPolyglot, CategoryXSSSVGNamespaceAbuse, CategoryXSSSVGUseExternal, CategoryXSSJavaScriptURL,
		CategoryXSSDataURL, CategoryXSSSVGScript, CategoryXSSDOMClobbering,
	},
	FacetCompliance: {
		CategoryOWASPLLM01, CategoryOWASPLLM02, CategoryOWASPLLM04, CategoryOWASPLLM05,
		CategoryOWASPLLM06, CategoryOWASPLLM08, CategoryOWASPLLM09, CategoryOWASPLLM10,
		CategoryMITREATLASTA0001, CategoryATLASPoison, CategoryATLASExfiltration, CategoryATLASJailbreak,
		CategoryEUAIActHighRisk, CategoryEUAIActTransparency, CategoryEUAIActHumanOversight, CategoryEUAIActRobustness,
		CategoryANPPersonalData, CategoryANPSpecialCategory, CategoryCUConsumerRights, CategoryCUMinorProtection,
		CategoryCCPAReference, CategoryISO27001Reference, CategoryLGPDReference, CategoryNISTCSFReference,
		CategoryPIPEDAReference, CategoryPOPIAReference, CategoryOWASPLLM10Unbounded, CategoryMITREATLASTA0002,
		CategoryEUAIActArticle10, CategoryMITREATLASTA0009, CategoryEUAIActArticle52,
	},
	FacetToxicity: {
		CategoryToxicityHate, CategoryToxicityInsult, CategoryToxicityObscene, CategoryToxicityThreat,
		CategoryToxicitySexual, CategoryToxicitySelfHarm, CategoryToxicityViolence,
	},
	FacetPromptInjection: {
		CategoryPIDirectOverride, CategoryPIIndirectInjection, CategoryPIJailbreak, CategoryPIRolePlayAttack,
	},
}

// categoryFacetIndex maps category strings to their facet for O(1) lookup.
var categoryFacetIndex map[string]Facet

func init() {
	categoryFacetIndex = make(map[string]Facet, len(AllCategories))
	for facet, cats := range FacetCategories {
		for _, cat := range cats {
			categoryFacetIndex[string(cat)] = facet
		}
	}
	categoryFacetIndex[string(CategorySourceCode)] = FacetSecrets
}

// FacetFromCategory returns the Facet for a given category string.
func FacetFromCategory(category string) Facet {
	if f, ok := categoryFacetIndex[category]; ok {
		return f
	}
	return ""
}

// Severity is the severity of the detection.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// AllSeverities is the closed set of valid severities.
var AllSeverities = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// UserAction is what the user did in response to a Lens warning.
type UserAction string

const (
	UserActionSendAnyway           UserAction = "send_anyway"
	UserActionRedact               UserAction = "redact"
	UserActionCancel               UserAction = "cancel"
	UserActionDismissFalsePositive UserAction = "dismiss_false_positive"
)

// AllUserActions is the closed set of valid user actions.
var AllUserActions = []UserAction{UserActionSendAnyway, UserActionRedact, UserActionCancel, UserActionDismissFalsePositive}

// Event is a single telemetry event from a Lens extension.
type Event struct {
	LensEventVersion int                `json:"lens_event_version"`
	DomainHash       string             `json:"domain_hash"`
	Facet            string             `json:"facet"`
	Category         string             `json:"category"`
	Severity         string             `json:"severity"`
	UserAction       string             `json:"user_action"`
	Timestamp        int64              `json:"timestamp"`
	ModelVersion     string             `json:"model_version"`
	LensVersion      string             `json:"lens_version"`
	Confidence       float64            `json:"confidence"`
	PatternID        string             `json:"pattern_id,omitempty"`
	MLScore          float64            `json:"ml_score,omitempty"`
	MLThreshold      float64            `json:"ml_threshold,omitempty"`
	FacetResults     map[string]float64 `json:"facet_results,omitempty"`
	ID               string             `json:"id,omitempty"`
}

// ErrInvalidEvent is returned by Validate for validation failures.
var ErrInvalidEvent = errors.New("invalid event")

// Validate enforces the v0.2 schema.
func (e *Event) Validate() error {
	if e.LensEventVersion != 1 {
		return fmt.Errorf("%w: lens_event_version must be 1, got %d", ErrInvalidEvent, e.LensEventVersion)
	}
	if len(e.DomainHash) != 16 {
		return fmt.Errorf("%w: domain_hash must be 16 hex chars, got %d", ErrInvalidEvent, len(e.DomainHash))
	}
	for _, c := range e.DomainHash {
		if !isLowerHex(c) {
			return fmt.Errorf("%w: domain_hash must be lowercase hex, got %q", ErrInvalidEvent, e.DomainHash)
		}
	}
	if !isValidFacet(e.Facet) {
		return fmt.Errorf("%w: facet %q not in %v", ErrInvalidEvent, e.Facet, AllFacets)
	}
	if !isValidCategoryForFacet(e.Facet, e.Category) {
		return fmt.Errorf("%w: category %q not valid for facet %q", ErrInvalidEvent, e.Category, e.Facet)
	}
	if !isValidSeverity(e.Severity) {
		return fmt.Errorf("%w: severity %q not in %v", ErrInvalidEvent, e.Severity, AllSeverities)
	}
	if !isValidUserAction(e.UserAction) {
		return fmt.Errorf("%w: user_action %q not in %v", ErrInvalidEvent, e.UserAction, AllUserActions)
	}
	now := time.Now().Unix()
	if e.Timestamp <= 0 {
		return fmt.Errorf("%w: timestamp must be positive", ErrInvalidEvent)
	}
	delta := e.Timestamp - now
	if delta < -24*3600 || delta > 24*3600 {
		return fmt.Errorf("%w: timestamp must be within ±24h of server clock", ErrInvalidEvent)
	}
	if e.ModelVersion == "" {
		return fmt.Errorf("%w: model_version must be non-empty", ErrInvalidEvent)
	}
	if e.LensVersion == "" {
		return fmt.Errorf("%w: lens_version must be non-empty", ErrInvalidEvent)
	}
	if e.Confidence < 0.0 || e.Confidence > 1.0 {
		return fmt.Errorf("%w: confidence must be in [0.0, 1.0], got %f", ErrInvalidEvent, e.Confidence)
	}
	if e.MLScore < 0.0 || e.MLScore > 1.0 {
		return fmt.Errorf("%w: ml_score must be in [0.0, 1.0], got %f", ErrInvalidEvent, e.MLScore)
	}
	if e.MLThreshold < 0.0 || e.MLThreshold > 1.0 {
		return fmt.Errorf("%w: ml_threshold must be in [0.0, 1.0], got %f", ErrInvalidEvent, e.MLThreshold)
	}
	return nil
}

func isValidFacet(f string) bool {
	for _, v := range AllFacets {
		if string(v) == f {
			return true
		}
	}
	return false
}

func isValidCategoryForFacet(facet, category string) bool {
	f := Facet(facet)
	cats, ok := FacetCategories[f]
	if !ok {
		return false
	}
	for _, c := range cats {
		if string(c) == category {
			return true
		}
	}
	if f == FacetSecrets && category == string(CategorySourceCode) {
		return true
	}
	return false
}

func isValidCategory(c string) bool {
	for _, v := range AllCategories {
		if string(v) == c {
			return true
		}
	}
	return false
}

func isValidSeverity(s string) bool {
	switch Severity(s) {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func isValidUserAction(u string) bool {
	for _, v := range AllUserActions {
		if string(v) == u {
			return true
		}
	}
	return false
}

func isLowerHex(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

func containsPlus(s string) bool {
	for _, c := range s {
		if c == '+' {
			return true
		}
	}
	return false
}

// decodeEvent parses a JSON event body into an Event struct.
// Disallows unknown fields as a privacy measure.
func decodeEvent(body []byte) (Event, error) {
	var e Event
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, fmt.Errorf("decode: %w", err)
	}
	return e, nil
}
