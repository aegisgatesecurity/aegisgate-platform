// SPDX-License-Identifier: Apache-2.0

// Package remediation provides the rule metadata database for the
// AegisGate Platform, ported from the AegisGate Scanner's
// pkg/output/rule_metadata.go.
//
// The database maps detection rule IDs to structured metadata including:
//
//   - CWE (Common Weakness Enumeration) identifiers
//   - OWASP LLM Top 10 (2025) category and name
//   - NIST AI RMF function references (Govern, Map, Measure, Manage)
//   - NIST CSF 2.0 subcategory references
//   - EU AI Act article references
//   - Human-readable descriptions
//   - Actionable remediation guidance
//   - Reference URLs to authoritative documentation
//
// # Lookup strategy
//
// GetRuleMetadata uses a three-tier lookup strategy:
//
//  1. Exact match against ruleMetadataMap for known rule IDs.
//  2. Prefix-based category matching via prefixMatchers for rules
//     that follow a naming convention (e.g., "secret_…", "xss_…").
//  3. A default entry with generic remediation guidance for any
//     rule that does not match the above.
//
// # Convenience helpers
//
// In addition to GetRuleMetadata and GetAllRuleMetadata, this package
// provides:
//
//   - GetRemediation: returns only the remediation text for a rule ID.
//   - GetOWASPMapping: returns CWE, NIST, and EU AI Act references for
//     an OWASP LLM Top 10 identifier.
//   - getRemediationForCategory: internal helper that returns
//     remediation text for a category prefix.
//
// # Canonical source
//
// The AegisGate Scanner remains the canonical source for rule metadata.
// This package mirrors its data to make remediation guidance available
// to the Platform without a cross-repository dependency. When new rules
// are added to the Scanner, the corresponding entries should be ported
// here as well.
package remediation
