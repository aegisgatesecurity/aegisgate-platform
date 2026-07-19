// SPDX-License-Identifier: Apache-2.0
// Attack category family/equivalent mappings (used by attacks_test.go).
package lenstest

// attackCategoryFamilies maps a category to its family prefix.
var attackCategoryFamilies = map[string]string{
	"pii_email":                   "pii",
	"pii_phone":                   "pii",
	"pii_ssn":                     "pii",
	"pii_credit_card":             "pii",
	"pii_bank_account":            "pii",
	"pii_date_of_birth":           "pii",
	"pii_driver_license":          "pii",
	"pii_health":                  "pii",
	"pii_ip_address":              "pii",
	"secret_aws_key":              "secret",
	"secret_anthropic_key":        "secret",
	"secret_openai_key":           "secret",
	"secret_google_api_key":       "secret",
	"secret_twilio_key":           "secret",
	"secret_sendgrid_key":         "secret",
	"secret_jwt":                  "secret",
	"secret_bearer_token":         "secret",
	"secret_database_url":         "secret",
	"secret_private_key":          "secret",
	"secret_webhook_secret":       "secret",
	"secret_api_key":              "secret",
	"harassment":                  "toxicity",
	"illegal":                     "toxicity",
	"self_harm":                   "toxicity",
	"violence":                    "toxicity",
	"weapons":                     "toxicity",
	"toxicity_custom":             "toxicity",
	"owasp_training_poisoning":    "owasp",
	"owasp_model_dos":             "owasp",
	"owasp_supply_chain":          "owasp",
	"owasp_insecure_plugin":       "owasp",
	"owasp_excessive_agency":      "owasp",
	"owasp_overreliance":          "owasp",
	"owasp_model_theft":           "owasp",
	"owasp_prompt_injection":      "owasp",
	"owasp_insecure_output":       "owasp",
	"atlas_configexfiltration":    "atlas",
	"atlas_contentinjection":      "atlas",
	"atlas_credentialforgery":     "atlas",
	"atlas_dataextraction":        "atlas",
	"atlas_defenseevasion":        "atlas",
	"atlas_denialofservice":       "atlas",
	"atlas_elevationabuse":        "atlas",
	"atlas_endpointdenial":        "atlas",
	"atlas_indirectinjection":     "atlas",
	"atlas_inhibitrecovery":       "atlas",
	"atlas_llmjailbreak":          "atlas",
	"atlas_mfabypass":             "atlas",
	"atlas_pluginexploitation":    "atlas",
	"atlas_promptextraction":      "atlas",
	"atlas_promptinjection":       "atlas",
	"atlas_resourceexhaustion":    "atlas",
	"atlas_vectordbpoisoning":     "atlas",
	"anp_guard_injection":         "anp_guard",
	"computeruse_guard_sensitive": "computeruse",
}

// attackCategoryEquivalents maps a category to sibling categories.
var attackCategoryEquivalents = map[string][]string{
	"pii_credit_card": {"computeruse_guard_sensitive"},
	"secret_api_key":  {"computeruse_guard_sensitive"},
}

// AttackCategoryFamiliesFor returns the families + equivalents for the
// given list of categories. Used by attacks_test.go for family fallback.
func AttackCategoryFamiliesFor(cats []string) []string {
	var fams []string
	for _, c := range cats {
		if fam, ok := attackCategoryFamilies[c]; ok {
			fams = append(fams, fam)
		}
		if equiv, ok := attackCategoryEquivalents[c]; ok {
			fams = append(fams, equiv...)
		}
	}
	return fams
}
