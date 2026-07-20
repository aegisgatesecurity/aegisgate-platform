# AegisGate Pricing

> **Source of truth** for the aegisgatesecurity.io pricing page. The static
> site at `docs/website/index.html` mirrors this content; when this file
> changes, the static site is regenerated.
>
> Last updated: 2026-06-06 (v3.3.0 — EU AI Act module)
> Founder-locked pricing decisions: see `plans/aegisgate-pricing-decisions-locked-2026-06-04`.

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
| **Professional** | **$499/mo** | **$4,990/yr** | EU enterprise, regulated industries |
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
| SOC 2             | $149/mo    | Developer+       | SOC 2 Type II control mapping, evidence collection — **framework stub (control definitions Q4 2026)** |
| ISO 42001         | $79/mo     | Professional+    | ISO/IEC 42001 AI management system controls — **framework stub (control definitions Q4 2026)** |
| FedRAMP           | $499/mo    | Professional+    | FedRAMP Moderate/High control mapping, continuous monitoring — **coming Q4 2026 (no code yet)** |
| FIPS 140-2/140-3  | $299/mo    | Professional+    | FIPS-validated cryptography, HSM integration — **coming Q4 2026 (no code yet)** |
| **EU AI Act** 🆕  | **$99/mo** | **Professional+** | **Required for high-risk AI systems in EU; 82 controls across 8 categories — fully implemented in v3.3.0** |

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
  EU AI Act, MITRE ATLAS, NIST AI RMF, OWASP in every scan. **SOC 2,
  ISO 42001, FedRAMP, and FIPS 140 modules register in your license
  but currently return 0 automated control findings** (see the table
  above for the implementation roadmap). If your compliance auditor
  asks for SOC 2 or ISO 42001 evidence in 2026, you currently need
  to export raw platform audit logs and frame them manually.

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
