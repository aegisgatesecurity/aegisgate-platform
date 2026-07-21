// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Compliance Framework Engine
// =========================================================================
//
// Core compliance framework engine for AegisGate. Implements pattern
// matching, framework assessment, evidence collection, and the
// public-facing API at /api/v1/compliance/*.
//
// Frameworks supported (7 advertised, 3 fully implemented):
//   - MITRE ATLAS     (pkg/compliance/atlas.go)         — full
//   - OWASP LLM Top 10 (pkg/compliance/owasp.go)         — full
//   - NIST AI RMF     (pkg/compliance/enterprise/nist/)  — full
//   - HIPAA           (pkg/compliance/hipaa/)            — full (premium/)
//   - PCI-DSS         (pkg/compliance/pci/)              — full (premium/)
//   - SOC 2           (pkg/compliance/soc2/)             — full (v3.4.0+ Path B partial: 5 of 8 controls automated)
//   - ISO 42001       (pkg/compliance/iso42001/)         — full (v3.4.0+ Path B partial: 5 of 8 controls automated)
//   - EU AI Act       (pkg/compliance/eu-ai-act/)        — full (9 of 82 controls automated)
//   - FedRAMP         (no code yet, Path B remaining)
//   - FIPS 140        (no code yet, Path B remaining)
//
// Framework gating uses HasImplementation: true/false in
// pkg/compliance/gating.go (the single source of truth for what
// is shipped vs. what is reserved). See also pkg/compliance/soc2_framework.go
// for the framework definition pattern.
//
// Pricing: 3 of 7 modules are $79-$499/mo add-ons; the other 4
// are "framework stub" or "coming Q4 2026" per content/pricing.md.
//
// =========================================================================

package compliance
