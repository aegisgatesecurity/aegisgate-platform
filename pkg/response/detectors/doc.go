// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Regex Detectors Package
// =========================================================================
//
// Response-side XSS and compliance detection for the response guard.
//
// XSS (12 patterns) and compliance (35 patterns) are delegated to the
// upstream scanner package (github.com/aegisgatesecurity/aegisgate/pkg/
// scanner) as the single source of truth. The scanner_adapter.go file
// bridges scanner.Finding types to detectors.Match types.
//
// The remaining detection categories (secrets, PII, OT protocols) were
// removed in favor of the upstream scanner, which already covers them
// with 200 patterns across 8 categories. The response guard uses its
// own PIIScanner and SecretDetector for response-side PII/secret
// detection with validation logic (Luhn checks, SSN range validation,
// masking/redaction).
//
// Lens parity is maintained via the upstream scanner patterns.
// =========================================================================
package detectors
