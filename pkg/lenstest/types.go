// SPDX-License-Identifier: Apache-2.0
// Shared types for the lenstest package.
package lenstest

// CanonicalEntry is one row of the per-pattern canonical corpus.
//
// Defined here (in package lenstest) so all subpackages can use it.
// The corpus data files (per_pattern.go, per_pattern_gen.go) live in
// pkg/lenstest/corpus/ and are also in package lenstest.
type CanonicalEntry struct {
	// Pattern identification (matches detectors/from_platform.js and
	// detectors/regex.js)
	Source   string
	Category string
	Name     string
	Severity string

	// Canonical test inputs
	MustTrigger    string
	MustNotTrigger string

	// Expected match string (for MustTrigger); used to verify
	// the detector returns the right substring, not just any match.
	ExpectedMatch string
}
