// SPDX-License-Identifier: Apache-2.0
// Helper: equivalence between hand-written and ported pattern names.
//
// The Lens detector runs hand-written patterns (regex.js) BEFORE
// ported patterns (from_platform.js). For some categories (PII,
// common secrets), the hand-written pattern is a subset of the
// ported one (e.g., both match AKIA... for AWS keys). When the
// hand-written fires first, the ported pattern's name is never
// returned by detect().
//
// For the per-pattern test, this means: when we test the ported
// pattern's canonical example, the actual detection comes back
// with the hand-written name, not the ported one. Both are
// correct detections of the same underlying PII/secret.
//
// This file maps the categories to the hand-written names that
// are equivalent. The test uses this map to know "any of these
// names is an acceptable detection".
package lenstest

// HandWrittenEquivalent returns the hand-written pattern name(s)
// that cover the same category as the given ported pattern name.
// Returns nil if no hand-written equivalent exists.
//
// This is used by the per-pattern test to accept either the
// hand-written OR the ported name as a valid detection.
//
// Source of truth: detectors/regex.js (the hand-written patterns).
var HandWrittenEquivalents = map[string][]string{
	// Hand-written -> ported equivalents.
	"email_v1":           {"secret_detector_secret_api_key_v1", "pii_scanner_pii_email_v1"},
	"phone_na_v1":        {"pii_scanner_pii_phone_v1"},
	"ssn_v1":             {"pii_scanner_pii_ssn_v1"},
	"credit_card_visa_v1":   {"pii_scanner_pii_credit_card_v1", "computeruse_guard_Computer_Use"},
	"credit_card_mastercard_v1": {"pii_scanner_pii_credit_card_v1", "computeruse_guard_Computer_Use"},
	"credit_card_amex_v1":     {"pii_scanner_pii_credit_card_v1", "computeruse_guard_Computer_Use"},
	"aws_access_key_v1":   {"secret_detector_secret_aws_key_v1"},
	"github_pat_v1":       {"secret_detector_secret_api_key_v1"},
	"github_oauth_v1":     {"secret_detector_secret_api_key_v1"},
	"stripe_live_key_v1":  {"secret_detector_secret_api_key_v1"},
	"google_api_key_v1":   {"secret_detector_secret_google_api_key_v1"},
	"rsa_private_key_v1":  {"secret_detector_secret_private_key_v1"},
}

// FindAcceptableNames returns the list of detection names that
// would be acceptable for the given canonical entry. Includes:
//   - The entry's own name (the ported pattern's name)
//   - The entry's category (matched as a category, not name)
//   - Any hand-written equivalent names
func FindAcceptableNames(e CanonicalEntry) []string {
	names := []string{e.Name}
	// Find hand-written equivalents (reverse map)
	for hwName, portedNames := range HandWrittenEquivalents {
		for _, pn := range portedNames {
			if pn == e.Name {
				names = append(names, hwName)
				break
			}
		}
	}
	return names
}