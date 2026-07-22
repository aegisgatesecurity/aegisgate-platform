# AegisGate Pricing

> **Source of truth** for the aegisgatesecurity.io pricing page. The static
> site at `docs/website/index.html` mirrors this content; when this file
> changes, the static site is regenerated.
>
> Last updated: 2026-07-22 (v3.5.0 — FedRAMP Path C: 60 controls, full cross-framework traceability)
> Founder-locked pricing decisions: see `plans/aegisgate-pricing-decisions-locked-2026-06-04`.

---

## 📚 Customer 1-pagers (linked from each tier/module below)

These 1-pagers explain the technical depth behind each tier and module
for sales engineers, security architects, and procurement teams. They
follow the established `docs/compliance/eu-ai-act.md` pattern
(self-attested disclaimer, what's covered, what's out of scope,
linkage to other modules, versioning).

| 1-pager | What it explains | Use case |
|---------|------------------|----------|
| [Trust Framework 1-pager](../docs/trust-framework.md) | The 6th pillar (per-agent identity, capability contracts, real-time trust scoring, signed attestations) | Sales engineer answering "how does AegisGate help with my SOC 2 / HIPAA / EU AI Act?" |
| [Federated IOC Library 1-pager](../docs/federated-ioc-library-1pager.md) | "1 customer's threat = all AegisGate customers protected" — the network effect | Sales engineer answering "what does 'federated' mean and why should I care?" |
| [EU AI Act 1-pager](../docs/compliance/eu-ai-act.md) | The 7th compliance framework (82 controls, 9 automated) | EU enterprise procurement (hard requirement) |
| [Lens → Platform Upsell 1-pager](../docs/lens-to-platform-upsell.md) | The 4-stage conversion funnel (individual → team → POC → production) | Growth/marketing and Lens users evaluating Platform |
| [Composite case study: Series-B SaaS + SOC 2](https://github.com/aegisgatesecurity/aegisgate-site/blob/main/content/blog/case-study-series-b-saas-soc2-with-trust-framework.md) | How a 200-person Series-B SaaS passed SOC 2 Type II in 90 days using AegisGate | Sales engineer and prospect evaluating the AegisGate value proposition |

The composite case study is **representative**, not a real customer.
It is built from anonymized patterns across multiple AegisGate
customers. We publish composite case studies to illustrate the value
of AegisGate for a customer segment without disclosing customer
information. See the case study document for our full
[customer reference policy](../docs/lens-to-platform-upsell.md#customer-reference-policy).

---

## 🟡 Test Mode (v3.3.0 Beta)

> **AegisGate v3.3.0 is in beta.** Stripe Buy Buttons on this page are in
> **test mode** — use the Stripe test card `4242 4242 4242 4242` with any
> future expiry and any CVC to simulate a purchase. **No real money is
> charged.** The flip to live mode is scheduled for v3.4.0 (after pentest
> + legal sign-off).

---

## Tier Subscription Prices

| Tier        | Monthly     | Annual       | Required for                     |
|-------------|-------------|--------------|----------------------------------|
| Community   | **Free**    | Free         | All open-source users            |
| Starter     | $29/mo      | $290/yr      | Solo devs, small projects        |
| Developer   | $79/mo      | $790/yr      | Small teams, production use      |
| **Professional** | **$499/mo** | **$4,990/yr** | EU enterprise, regulated industries, SOC 2 / EU AI Act evidence |
| Enterprise  | $2,000/mo   | $24,000/yr   | Series-B+ SaaS, air-gapped, HSM  |

> Pricing locked 2026-06-04 (v3.2.0 release). Existing customers keep
> their price forever (Q2: lock-in at purchase price).

---

## Compliance Modules (7 total — v3.3.0)

Modules are **add-ons** purchased on top of any paid tier. They activate
instantly via the Stripe webhook (Q1: instant via webhook).

| Module            | Price      | Required Tier    | Description |
|-------------------|-----------:|------------------|-------------|
| HIPAA             | $99/mo     | Developer+       | HIPAA-compliant logging, PHI detection, BAA support — **fully implemented** |
| PCI-DSS           | $99/mo     | Developer+       | Payment card data detection, PCI-scoped audit logs — **fully implemented** |
| SOC 2             | $149/mo    | Developer+       | SOC 2 Type II Trust Service Criteria, 5 automated controls (CC6.1, CC6.2, CC6.3, CC6.6, CC6.7) + 10 evidence-mapped — **fully implemented** |
| ISO 42001         | $79/mo     | Professional+    | ISO/IEC 42001 AI Management System, 5 automated controls (5.2, 6.1, 7.5, 8.2, 9.1) + 7 evidence-mapped — **fully implemented** |
| FIPS 140-2/140-3  | $299/mo    | Professional+    | FIPS 140 cryptographic module compliance, 8 automated controls (mode enabled, approved ciphers, TLS 1.2+, approved hashes, key sizes, self-test, audit logging) + 2 manual (CMVP, HSM) — **fully implemented. Note: AegisGate is FIPS-compliant (uses FIPS-approved algorithms) but the Go runtime is not CMVP-validated; federal agencies need a CMVP-validated execution environment.** |
| FedRAMP           | $499/mo    | Professional+    | FedRAMP Moderate (NIST 800-53 Rev. 5) — **60 in-scope controls across 11 families (AC, AU, IA, SC, CM, SI, IR, RA, CA, SA, SR). 38 automated (AegisGate scanner checks) + 22 evidence-mapped (AegisGate generates the technical evidence for the customer's A&A package). Full cross-framework traceability: every FedRAMP control maps to SOC 2, ISO 27001, HIPAA, PCI, NIST CSF, CIS, OWASP, and 8 other frameworks.** AegisGate is NOT a FedRAMP-accredited 3PAO; the 3PAO assessment and ATO issuance is the customer's responsibility. |
| **EU AI Act** 🆕  | **$99/mo** | **Professional+** | **Required for high-risk AI systems in EU; 82 controls across 8 categories — 9 automated, 73 manual. See [docs/compliance/eu-ai-act.md](../docs/compliance/eu-ai-act.md) and [plans/EU-AI-ACT-COVERAGE-AUDIT-2026-07-21.md](../plans/EU-AI-ACT-COVERAGE-AUDIT-2026-07-21.md) for the manual controls analysis.** |

### 🆕 EU AI Act Compliance Module (v3.3.0)

The **7th compliance framework** in AegisGate. Regulation 2024/1689
("EU AI Act") is in phased application — GPAI (General-Purpose AI)
provisions apply from August 2026, high-risk system classifications
(Annex III) are operative. **EU enterprise procurement teams ask
"is this vendor EU AI Act-aware?"** as a hard requirement.

- **82 controls** across 8 categories
- **Articles covered:** 5 (Prohibited Practices), 9 (Risk Management),
  10 (Data Governance), 11 (Technical Documentation), 12 (Record Keeping),
  13 (Transparency), 14 (Human Oversight), 15 (Accuracy/Robustness/
  Cybersecurity), 51-55 (GPAI Models)
- **Pricing:** $99/mo, Professional+ tier required (founder-locked 2026-06-06)
- **9 of 82 controls are automated** (prohibited practice pattern
  detection, risk management, technical documentation, automatic
  logging, transparency, human oversight, accuracy/robustness, data
  poisoning, prompt injection). Remaining 73 are manual review items
  for the customer's compliance team.
- **Documentation:** See `docs/compliance/eu-ai-act.md` for the
  customer 1-pager and `plans/EU-AI-ACT-CONTROL-MAPPING.md` for the
  full internal control-to-pattern mapping.

---

## What Buying Includes

- **All Community features** (MITRE ATLAS, NIST AI RMF, OWASP LLM Top 10,
  basic secret/PII/prompt-injection scanning) come **free with every tier**
  (per founder mandate — never paywalled).
- **Module** + **tier** in your subscription: scanned reports include
  all enabled frameworks. A Pro + EU AI Act customer sees HIPAA, PCI,
  EU AI Act, MITRE ATLAS, NIST AI RMF, OWASP in every scan. SOC 2
  has 5 automated + 10 evidence-mapped controls. ISO 42001 has 5
  automated + 7 evidence-mapped. FedRAMP has 60 in-scope controls
  (38 automated + 22 evidence-mapped) across 11 NIST 800-53 families
  with full cross-framework traceability to 15 frameworks. FIPS 140
  has 8 automated + 2 manual. If your compliance auditor asks for
  evidence, the platform generates the package from automated controls
  + the Trust Framework's signed attestations.
- **Trust Framework** (Professional+ tier, included): per-agent
  cryptographic identity (ECDSA P-256), capability contracts with
  fail-closed enforcement, real-time trust scoring, and signed
  attestations. The Trust Framework is the **primary evidence source**
  for SOC 2, HIPAA, and EU AI Act audits — see the
  [composite case study](https://github.com/aegisgatesecurity/aegisgate-site/blob/main/content/blog/case-study-series-b-saas-soc2-with-trust-framework.md)
  for a 90-day SOC 2 Type II example. Full 1-pager at
  [docs/trust-framework.md](../docs/trust-framework.md).
- **Federated IOC library** (Professional+ tier, included): opt-in
  sharing of detected threats across AegisGate instances. "1 customer's
  threat = all AegisGate customers protected." See the
  [1-pager](../docs/federated-ioc-library-1pager.md) for the value
  proposition and the 4 design principles (hash-based, opt-in/opt-out
  serverless, self-verifying, privacy-first).
- **FedRAMP** (Professional+ tier, $499/mo add-on): 60 in-scope
  FedRAMP Moderate controls (NIST 800-53 Rev. 5) across 11 families
  (AC, AU, IA, SC, CM, SI, IR, RA, CA, SA, SR). 38 are automated
  (AegisGate scanner checks), 22 are evidence-mapped (AegisGate
  generates the technical evidence for the customer's A&A package).
  Every control maps to SOC 2, ISO 27001, HIPAA, PCI, NIST CSF, CIS,
  OWASP, and 8 other frameworks via the cross-framework traceability
  engine. See `pkg/compliance/fedramp/` for the implementation.
  **Important**: AegisGate is NOT a FedRAMP-accredited 3PAO. The
  platform generates the technical evidence; the 3PAO assessment
  and ATO issuance is the customer's responsibility.
- **FIPS 140-2/140-3** (Professional+ tier, $299/mo add-on): cryptographic
  module compliance. 8 of 10 controls are automated (FIPS mode enabled,
  approved ciphers, TLS 1.2+, approved hashes, key sizes, self-test,
  audit logging). 2 are manual (CMVP validation, HSM integration).
  See `pkg/compliance/fips/` for the implementation. **Important**:
  AegisGate is FIPS-compliant (uses FIPS-approved algorithms via Go stdlib)
  but the Go runtime itself is not a CMVP-validated module. Customers
  who require CMVP-validated crypto (federal agencies, defense) must
  integrate a CMVP-validated module (e.g., via PKCS#11). The FIPS
  module is the right architectural foundation for that integration;
  the integration itself is the customer's responsibility.

---

## Legal

By purchasing you agree to our [Terms of Service] [Privacy Policy]
[Data Processing Agreement (DPA)]. Module purchases are non-refundable
once the Stripe webhook activates the module on your license, except
as required by EU consumer protection law for the 14-day withdrawal
period.

[Terms of Service]: https://aegisgatesecurity.io/terms
[Privacy Policy]: https://aegisgatesecurity.io/privacy
[Data Processing Agreement (DPA)]: https://aegisgatesecurity.io/dpa
