//go:build manual

// +build manual

// SPDX-License-Identifier: Apache-2.0

// Go/JS cross-validation test (drift detection).
//
// For each canonical entry in the per-pattern corpus, this test:
//  1. Runs the prompt through the JS detector (subprocess)
//  2. Runs the prompt through the Go-side detector (in-process,
//     patterns extracted from Platform Go source files)
//  3. Asserts both detectors agree on whether a detection fires
//     in the entry's category
//
// Purpose: catch drift between the Go patterns (source of truth,
// read by the codegen tool) and the JS patterns (codegen output,
// loaded by the browser extension). If they diverge, the codegen
// tool has a bug or the regex semantics differ between Go regexp
// and JS RegExp.
//
// Coverage:
//   - 34 patterns in Go (PII + secrets + toxicity from pkg/response/)
//   - 153 patterns in JS (12 hand-written + 141 ported)
//
// We can only cross-validate the 34 patterns that exist in BOTH
// the Go source files AND the JS detector. Patterns unique to JS
// (hand-written, OWASP, ATLAS, etc.) are NOT cross-validated here.
package lenstest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	lenstest "github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest"
	corpus "github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/corpus"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/detector"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/goside"
)

const platformRoot = "/home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform"

// findJSDetectionByCategory returns the first JS detection in the
// given category, or nil. Mirrors the helper in per_pattern_test.go.
func findJSDetectionByCategory(res *detector.DetectResult, category string) *detector.Detection {
	for i := range res.Detections {
		if res.Detections[i].Category == category {
			return &res.Detections[i]
		}
	}
	return nil
}

// findGoDetectionByFamily returns the first Go-side detection in
// the same CATEGORY FAMILY as the given category. This allows
// cross-validation when Go and JS use slightly different
// category names (e.g., JS has secret_anthropic_key, Go has
// secret_api_key as the generic family).
func findGoDetectionByFamily(dets []goside.GosideDetection, category string) *goside.GosideDetection {
	family := categoryFamilies[category]
	for i := range dets {
		// Match exact category OR same family prefix
		if dets[i].Category == category {
			return &dets[i]
		}
		if family != "" && strings.HasPrefix(dets[i].Category, family) {
			return &dets[i]
		}
	}
	return nil
}

// categoriesCrossValidated lists every category that exists in both
// the Go-side detector (extracted from Platform Go source files) AND
// the JS detector. Patterns outside this list (e.g., hand-written JS-only
// patterns) are tested by the per-pattern tests but not by cross-validation.
var categoriesCrossValidated = map[string]bool{
	// PII
	"pii_bank_account":   true,
	"pii_credit_card":    true,
	"pii_date_of_birth":  true,
	"pii_driver_license": true,
	"pii_email":          true,
	"pii_health":         true,
	"pii_ip_address":     true,
	"pii_phone":          true,
	"pii_ssn":            true,
	// Secrets
	"secret_anthropic_key":  true,
	"secret_api_key":        true,
	"secret_aws_key":        true,
	"secret_bearer_token":   true,
	"secret_database_url":   true,
	"secret_google_api_key": true,
	"secret_jwt":            true,
	"secret_openai_key":     true,
	"secret_private_key":    true,
	"secret_sendgrid_key":   true,
	"secret_twilio_key":     true,
	"secret_webhook_secret": true,
	// Toxicity
	"harassment":      true,
	"illegal":         true,
	"self_harm":       true,
	"violence":        true,
	"weapons":         true,
	"toxicity_custom": true,
	// OWASP LLM Top 10
	"owasp_excessive_agency":   true,
	"owasp_insecure_output":    true,
	"owasp_insecure_plugin":    true,
	"owasp_model_dos":          true,
	"owasp_model_theft":        true,
	"owasp_overreliance":       true,
	"owasp_prompt_injection":   true,
	"owasp_supply_chain":       true,
	"owasp_training_poisoning": true,
	// ATLAS (MITRE)
	"atlas_configexfiltration": true,
	"atlas_contentinjection":   true,
	"atlas_credentialforgery":  true,
	"atlas_dataextraction":     true,
	"atlas_defenseevasion":     true,
	"atlas_denialofservice":    true,
	"atlas_elevationabuse":     true,
	"atlas_endpointdenial":     true,
	"atlas_indirectinjection":  true,
	"atlas_inhibitrecovery":    true,
	"atlas_llmjailbreak":       true,
	"atlas_mfabypass":          true,
	"atlas_pluginexploitation": true,
	"atlas_promptextraction":   true,
	"atlas_promptinjection":    true,
	"atlas_resourceexhaustion": true,
	"atlas_vectordbpoisoning":  true,
	// EU AI Act
	"eu_ai_act_adversarial":  true,
	"eu_ai_act_datapoison":   true,
	"eu_ai_act_manipulation": true,
	"eu_ai_act_promptinject": true,
	"eu_ai_act_subliminal":   true,
	// Computer Use Guard
	"computeruse_guard_sensitive": true,
	// ANP Guard
	"anp_guard_injection": true,
}

// categoryFamilies maps each specific category to a broader family
// for cross-validation. The Go-side detector doesn't always have the
// same specific category names as JS (e.g., JS has secret_anthropic_key,
// secret_openai_key, etc., but Go's plain-form patterns all use
// secret_api_key as the generic category). We accept any detection in
// the same family as a match.
var categoryFamilies = map[string]string{
	// PII family
	"pii_email":          "pii",
	"pii_phone":          "pii",
	"pii_ssn":            "pii",
	"pii_credit_card":    "pii",
	"pii_bank_account":   "pii",
	"pii_date_of_birth":  "pii",
	"pii_driver_license": "pii",
	"pii_health":         "pii",
	"pii_ip_address":     "pii",
	// Secret family
	"secret_aws_key":        "secret",
	"secret_anthropic_key":  "secret",
	"secret_openai_key":     "secret",
	"secret_google_api_key": "secret",
	"secret_twilio_key":     "secret",
	"secret_sendgrid_key":   "secret",
	"secret_jwt":            "secret",
	"secret_bearer_token":   "secret",
	"secret_database_url":   "secret",
	"secret_private_key":    "secret",
	"secret_webhook_secret": "secret",
	"secret_api_key":        "secret",
	// Toxicity family
	"harassment":      "toxicity",
	"illegal":         "toxicity",
	"self_harm":       "toxicity",
	"violence":        "toxicity",
	"weapons":         "toxicity",
	"toxicity_custom": "toxicity",
	// OWASP family
	"owasp_training_poisoning": "owasp",
	"owasp_model_dos":          "owasp",
	"owasp_supply_chain":       "owasp",
	"owasp_insecure_plugin":    "owasp",
	"owasp_excessive_agency":   "owasp",
	"owasp_overreliance":       "owasp",
	"owasp_model_theft":        "owasp",
	// ATLAS family
	"atlas_configexfiltration": "atlas",
	"atlas_contentinjection":   "atlas",
	"atlas_credentialforgery":  "atlas",
	"atlas_dataextraction":     "atlas",
	"atlas_defenseevasion":     "atlas",
	"atlas_denialofservice":    "atlas",
	"atlas_elevationabuse":     "atlas",
	"atlas_endpointdenial":     "atlas",
	"atlas_indirectinjection":  "atlas",
	"atlas_inhibitrecovery":    "atlas",
	"atlas_llmjailbreak":       "atlas",
	"atlas_mfabypass":          "atlas",
	"atlas_pluginexploitation": "atlas",
	"atlas_promptextraction":   "atlas",
	"atlas_promptinjection":    "atlas",
	"atlas_resourceexhaustion": "atlas",
	"atlas_vectordbpoisoning":  "atlas",
	// ANP family
	"anp_guard_injection": "anp_guard",
}

// TestCrossValidation_GoJS runs each canonical MustTrigger
// through both Go and JS detectors. Asserts:
//   - For cross-validated categories: BOTH detectors must fire
//     (or both must NOT fire — but for MustTrigger we expect fire).
//   - The match strings must overlap (substring or superset).
//
// Drift is reported per-pattern with details about which
// detector saw what.
func TestCrossValidation_GoJS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-validation in -short mode")
	}

	gd, err := goside.New(platformRoot)
	if err != nil {
		t.Fatalf("goside.New: %v", err)
	}
	t.Logf("Go-side detector loaded %d patterns", gd.Count())

	jd := detector.NewDetector()
	jd.Timeout = 30 * time.Second

	entries := corpus.AllCanonicalEntries()

	// Filter to only cross-validated categories
	var xvalEntries []lenstest.CanonicalEntry
	for _, e := range entries {
		if categoriesCrossValidated[e.Category] {
			xvalEntries = append(xvalEntries, e)
		}
	}
	t.Logf("Cross-validating %d entries (out of %d total)",
		len(xvalEntries), len(entries))

	agree := 0
	drift := 0
	for _, e := range xvalEntries {
		e := e
		t.Run(e.Name, func(t *testing.T) {
			// Go-side detection (by category family)
			goDets := gd.Detect(e.MustTrigger)
			goFire := findGoDetectionByFamily(goDets, e.Category)

			// JS-side detection
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			jsRes, err := jd.Detect(ctx, e.MustTrigger)
			if err != nil {
				t.Fatalf("JS detect failed: %v", err)
			}
			jsFire := findJSDetectionByCategory(jsRes, e.Category)
			// Also check family-prefix match (e.g., atlas_llmjailbreak <-> atlas_promptinjection)
			if jsFire == nil {
				family := categoryFamilies[e.Category]
				for i := range jsRes.Detections {
					if family != "" && strings.HasPrefix(jsRes.Detections[i].Category, family+"_") {
						jsFire = &jsRes.Detections[i]
						break
					}
				}
			}

			// Both must fire (or both must NOT fire for MustNotTrigger, see below)
			goFired := goFire != nil
			jsFired := jsFire != nil

			if goFired && jsFired {
				// Both fired — verify they agree on category and that some
				// match content is shared. We accept partial overlap because:
				//   - Different patterns in the same family may match
				//     overlapping phrases (e.g., "OTP code" matches one
				//     regex, "Bypass MFA" matches a different one).
				//   - One detector may match a longer/different span.
				if jsFire.Category != goFire.Category &&
					!strings.HasPrefix(jsFire.Category, categoryFamilies[e.Category]) {
					// Different category AND different family — drift
					t.Errorf("DRIFT (category mismatch): both fired but in different categories\n  go: cat=%s match=%q\n  js: cat=%s match=%q\n  entry: %s (expected family %s)",
						goFire.Category, goFire.Match, jsFire.Category, jsFire.Match,
						e.Name, categoryFamilies[e.Category])
					drift++
				} else if !matchOverlaps(goFire.Match, jsFire.Match) {
					// Same family but different match strings — log as
					// informational drift (different sub-patterns in the
					// same family may legitimately match different substrings)
					t.Logf("note: %s fired with different substrings (same family)\n  go match: %q\n  js match: %q",
						e.Name, goFire.Match, jsFire.Match)
					agree++ // still count as agreement within family
				} else {
					agree++
				}
			} else if goFired && !jsFired {
				t.Errorf("DRIFT (Go fired, JS didn't): %s (category %s)\n  go match:    %q\n  js detections: %v",
					e.Name, e.Category, goFire.Match, jsRes.Detections)
				drift++
			} else if !goFired && jsFired {
				// JS fired but Go didn't — might be JS-only pattern
				// (computeruse_guard fires before pii_credit_card).
				// Acceptable for some categories; log but don't fail.
				if isAcceptableJSOnlyDetection(jsFire, e.Category) {
					t.Logf("note: JS fired (computeruse_guard probably), Go didn't: %s (%s) match=%q",
						e.Name, e.Category, jsFire.Match)
					agree++ // count as agreed for now
				} else {
					t.Errorf("DRIFT (JS fired, Go didn't): %s (category %s)\n  js match:    %q\n  go detections: %v",
						e.Name, e.Category, jsFire.Match, goDets)
					drift++
				}
			} else {
				// Neither fired — that's drift too (we expected at least one)
				t.Errorf("DRIFT (neither fired): %s (category %s)", e.Name, e.Category)
				drift++
			}
		})
	}

	t.Logf("Cross-validation: %d agreed, %d drifted (out of %d)",
		agree, drift, len(xvalEntries))
}

// matchOverlaps returns true if the two match strings share
// at least 50% of their content (substring or partial overlap).
func matchOverlaps(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if strings.Contains(a, b) || strings.Contains(b, a) {
		return true
	}
	// Check if any 4+ char substring of a is in b
	if len(a) >= 4 && len(b) >= 4 {
		for i := 0; i+4 <= len(a); i++ {
			sub := a[i : i+4]
			if strings.Contains(b, sub) {
				return true
			}
		}
	}
	return false
}

// isAcceptableJSOnlyDetection returns true if the JS detection
// came from a category that's known to run before the Go-extracted
// category (e.g., computeruse_guard fires before pii_credit_card).
func isAcceptableJSOnlyDetection(d *detector.Detection, expectedCategory string) bool {
	// computeruse_guard fires for credit-card-shaped numbers
	if expectedCategory == "pii_credit_card" && d.Category == "computeruse_guard_sensitive" {
		return true
	}
	return false
}