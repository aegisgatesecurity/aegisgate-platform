// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Compliance Framework Engine
// =========================================================================
//
// Core compliance framework engine for AegisGate. Implements pattern
// matching, framework assessment, evidence collection, and the
// public-facing API at /api/v1/compliance/*.
//
// Frameworks supported (31 frameworks, all with HasImplementation: true in
// pkg/compliance/gating.go):
//   - MITRE ATLAS      (pkg/compliance/atlas.go)          — full
//   - OWASP LLM Top 10 (pkg/compliance/owasp.go)          — full
//   - OWASP Web Top 10 (pkg/compliance/owasp_web/)        — full
//   - NIST AI RMF 1.0  (pkg/compliance/nist_ai_rmf/)       — full
//   - HIPAA            (pkg/compliance/hipaa/)             — full
//   - PCI-DSS          (pkg/compliance/pci/)               — full
//   - SOC 2            (pkg/compliance/soc2/)              — full
//   - ISO 27001        (pkg/compliance/iso27001/)          — full
//   - ISO 42001        (pkg/compliance/iso42001/)          — full
//   - EU AI Act        (pkg/compliance/eu_ai_act/)         — full
//   - GDPR             (pkg/compliance/community/gdpr/)    — full
//   - CCPA/CPRA        (pkg/compliance/ccpa/)              — full
//   - FedRAMP          (pkg/compliance/fedramp/)           — full (150 controls)
//   - FIPS 140-2/3     (pkg/compliance/fips/)              — full
//   - CIS              (pkg/compliance/cis/)               — full
//   - NIST CSF         (pkg/compliance/nist_csf/)          — full
//   - CSA STAR         (pkg/compliance/csa_star/)         — full
//   - NIST AI 600-1    (pkg/compliance/nist_ai_600_1/)    — full
//   - SOX              (pkg/compliance/sox/)               — full
//   - GLBA             (pkg/compliance/glba/)              — full
//   - CJIS             (pkg/compliance/cjis/)              — full
//   - NERC CIP         (pkg/compliance/nerc_cip/)         — full
//   - FERPA            (pkg/compliance/ferpa/)             — full
//   - HITECH           (pkg/compliance/hitech/)           — full
//   - FFIEC            (pkg/compliance/ffiec/)             — full
//   - TSA SD           (pkg/compliance/tsa_sd/)           — full
//   Plus additional frameworks registered in gating.go.
//
// Framework gating uses HasImplementation: true/false in
// pkg/compliance/gating.go (the single source of truth for what
// is shipped vs. what is reserved). See also pkg/compliance/soc2_framework.go
// for the framework definition pattern.
//
// Pricing: framework tier-inclusion is defined in gating.go
// (Community=6, Developer=8, Professional=17, Enterprise=20).
// See https://aegisgatesecurity.io/pricing/ for current pricing.
//
// =========================================================================

package compliance
