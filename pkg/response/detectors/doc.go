// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Regex Detectors Package
// =========================================================================
//
// Port of the AegisGate Lens regex detectors (176 patterns across 8
// categories) to Go. These patterns are maintained in parity with the
// Lens JavaScript implementation at:
//
//	aegisgate-lens/src/detectors/regex/
//
// Categories:
//   - secrets (45 patterns)
//   - pii-us-core (26 patterns)
//   - pii-us-extended (13 patterns)
//   - pii-financial (12 patterns)
//   - pii-international (24 patterns)
//   - xss (12 patterns)
//   - compliance (35 patterns)
//   - ot-protocols (9 patterns)
//
// Each pattern includes a severity level (critical, high, medium, low)
// and a confidence score. The regex strings are identical to the Lens
// versions (adapted from JavaScript /g flag to Go regexp.Regexp syntax).
// =========================================================================
package detectors
