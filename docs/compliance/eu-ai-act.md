# AegisGate EU AI Act Compliance (1-pager)

**Status:** v3.3.0 (shipped 2026-06-06)  
**Last reviewed:** 2026-06-06  
**Audience:** AegisGate customers evaluating EU AI Act readiness, EU enterprise procurement teams, and AegisGate sales engineers answering framework-coverage questions.

This document is a 1-page summary. The full control-to-AegisGate-detection-pattern mapping is documented internally (82 controls). The Go implementation lives at `pkg/compliance/eu-ai-act/` (4 files, 82 controls).

---

## What is the EU AI Act?

Regulation 2024/1689, in phased application from 2025-02-02. As of August 2026 the GPAI (General-Purpose AI) provisions apply; high-risk system classifications (Annex III) are operative; the 2027-08-02 deadline for legacy high-risk system conformity is on the horizon. The Act is **the world's only comprehensive AI law in force**, and EU enterprise procurement teams increasingly ask *"is this vendor EU AI Act-aware?"* as a hard requirement.

## What AegisGate covers

| Category | Articles | Controls | Severity | Automated? |
|----------|----------|----------|----------|------------|
| Prohibited practices | Art 5 | 8 | Critical | Yes (pattern scan) |
| High-risk risk management | Art 9 | 10 | Critical | Yes (process + doc check) |
| Data and data governance | Art 10 | 8 | High | Partial (manual review) |
| Technical documentation | Art 11 | 5 | High | Yes (artifact check) |
| Record-keeping / logging | Art 12 | 5 | High | Yes (log integrity check) |
| Transparency | Art 13 | 8 | High | Yes (disclosure check) |
| Human oversight | Art 14 | 6 | High | Yes (HITL marker check) |
| Accuracy, robustness, cybersecurity | Art 15 | 12 | Critical | Yes (accuracy/poisoning scan) |
| GPAI models | Art 51-55 | 10 | High | Partial (manual review) |
| AegisGate AI-specific | n/a | 10 | Medium | Yes (prompt injection, etc.) |
| **TOTAL** | | **82** | | **9 automated + 73 manual** |

All 82 controls are registered in the Go sub-package (`pkg/compliance/eu-ai-act/controls.go`). 9 have automated `CheckFunc` implementations in `eu_ai_act.go`; the remaining 73 are manual-review controls that the customer or auditor verifies against documented evidence (this mirrors the HIPAA sub-package's mix of automated + manual controls).

## What's enforced vs. recommended

- **Enforced by AegisGate at runtime** (9 controls): the platform scans incoming requests and configurations for prohibited practices (Art 5), risk management evidence (Art 9), technical documentation artifacts (Art 11), automatic logging (Art 12), transparency disclosures (Art 13), human oversight markers (Art 14), accuracy/robustness testing (Art 15), data/model poisoning patterns (Art 15), and prompt injection attempts (AI-001). Failures generate compliance events; critical failures can be configured to block the request.
- **Recommended for compliance evidence** (73 controls): the platform generates the report and audit-trail; the customer or auditor verifies the underlying practice exists. This is the right architecture: AegisGate is a **gateway**, not a quality management system or a documentation repository. We surface the controls; you own the compliance program.

## Tier & pricing

- **Tier required:** Professional+ (founder-locked 2026-06-06)
- **Price:** $99/mo add-on (matches HIPAA/PCI convention; unblocks EU Series-B SaaS upsell)
- **License module key:** `eu_ai_act`

To enable: buy the EU AI Act module in the customer portal; the license webhook activates the framework in your Compliance Scan Engine. Until the module is enabled, the EU AI Act row in scan reports shows `Enforced: false` with `Reason: module_not_owned`.

## What AegisGate does NOT cover (out of scope)

- **Notary / conformity assessment.** AegisGate is a compliance *scanning* tool, not a Notified Body or a conformity assessment provider. The Art 43 conformity assessment process is the customer's responsibility.
- **Quality management system (Art 17).** AegisGate does not host your QMS; we verify the markers are present in your configuration.
- **Post-market monitoring (Art 72) plan hosting.** We generate the event stream; you own the monitoring plan.
- **Serious-incident reporting (Art 73).** We surface the incidents in the audit log; you report to the AI Office / national authority.
- **Fundamental rights impact assessment (Art 27).** This is a deployer-side (customer) responsibility, not a vendor responsibility.

These items are explicitly out of scope for a security gateway. We tell you this up front rather than over-claim coverage.

## How to use the EU AI Act module

1. **Customer portal → Compliance tab → EU AI Act row.** Shows `Enforced: true`, control count (82), and current compliance percentage.
2. **`/api/v1/compliance/scan?framework=eu_ai_act`** returns a `FrameworkScanResult` with per-control status.
3. **Customer-side compliance dashboard** consumes the scan report and shows drill-down per control (compliant / partial / non-compliant) with remediation text.

For each non-compliant control, the `Remediation` field gives a short hint. For full evidence collection (e.g., "show me the Art 14 human-oversight evidence for the 2026-05 audit"), see the audit log; AegisGate timestamps all compliance-relevant events with cryptographic attestation (v3.2.0 Trust Framework).

## Linkage to other AegisGate modules

The EU AI Act module is **complementary** to other AegisGate frameworks, not a replacement:

- **HIPAA + EU AI Act**: many US-healthcare EU subsidiaries need both. Both are $99/mo on Professional+. The Art 9 risk-management controls overlap with HIPAA's risk analysis requirement; the Art 12 logging controls overlap with HIPAA's audit control requirement. AegisGate reports compliance per framework but the underlying scanner runs once and maps to all registered frameworks.
- **ISO 42001 + EU AI Act**: ISO 42001 is the AI management system standard. EU AI Act is the regulation. A customer implementing ISO 42001 will be ~60% of the way to EU AI Act compliance. The AegisGate scan engine reports both side-by-side.
- **SOC 2 + EU AI Act**: SOC 2 covers the security-program controls; EU AI Act covers the AI-specific controls. Both are Professional+ tier.

## Self-attested, not third-party validated

> AegisGate's EU AI Act module is **self-attested**. AegisGate is not a Notified Body, accredited certification body, or law firm. The control-to-pattern mapping is engineered by AegisGate staff based on the published text of Regulation 2024/1689 and is reviewed internally for accuracy. Customers should consult qualified legal counsel for opinion-of-counsel on their specific EU AI Act obligations.

This is the same posture as the HIPAA, PCI, and SOC 2 modules. We engineer the scanner; a Notified Body or counsel provides the certification / legal opinion.

## References

- Regulation 2024/1689 (full text): https://eur-lex.europa.eu/eli/reg/2024/1689/oj
- Article 5 (prohibited practices): https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_5
- Article 9 (risk management): https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_9
- Annex III (high-risk classifications): https://eur-lex.europa.eu/eli/reg/2024/1689/oj#anx_III
- Article 27 (fundamental rights impact assessment for deployers)
- Article 43 (conformity assessment)
- Article 50 (transparency obligations for providers of certain AI systems)
- Article 51-55 (GPAI obligations)
- Article 72 (post-market monitoring)
- Article 73 (serious-incident reporting)

## Versioning

| AegisGate version | EU AI Act status |
|-------------------|------------------|
| v3.2.0 and earlier | Not present |
| **v3.3.0** (this release) | **82 controls, 9 automated, Professional+ tier, $99/mo** |
| v3.4.0 (planned) | Add Art 50 transparency (chatbot / deepfake / biometric) automated checks; tighten Art 9 risk-management evidence |
| v3.5.0 (planned) | Add Art 27 fundamental rights impact assessment template; integrate with the Trust Framework for cryptographic evidence attestation |

---

*Document version: 1.0*  
*Last updated: 2026-06-06*  
*AegisGate Platform v3.3.0+*
