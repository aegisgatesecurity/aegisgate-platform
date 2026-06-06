# AegisGate Changelog

> **Source of truth** for the aegisgatesecurity.io changelog page. The
> static site at `docs/website/index.html` mirrors this content.
>
> For the full engineering changelog (per-commit, per-PR detail), see
> `CHANGELOG.md` in the platform repository.
>
> Last updated: 2026-06-06 (v3.3.0 — EU AI Act)

---

## [3.3.0] - 2026-06-06 - EU AI Act + Beta Readiness 🆕

> **Status: Beta release.** v3.3.0 ships the EU AI Act compliance
> module and prepares AegisGate for beta-readiness. **All Buy Buttons
> are in Stripe test mode** — use card `4242 4242 4242 4242` to
> simulate a purchase. Public commercial launch (live mode) is
> deferred to v3.4.0+ pending pentest + legal sign-off.

### 🆕 EU AI Act Compliance Module

The headline feature of v3.3.0. AegisGate becomes the **first AI
security gateway with full EU AI Act (Regulation 2024/1689) coverage**
out of the box.

- **82 controls** spanning Articles 5, 9, 10, 11, 12, 13, 14, 15, 51-55
- **8 categories**: Prohibited Practices, Risk Management, Data
  Governance, Technical Documentation, Record Keeping, Transparency,
  Human Oversight, Accuracy/Robustness/Cybersecurity, GPAI Models,
  plus 10 AegisGate AI extensions
- **9 of 82 controls are automated** via AegisGate's existing detection
  patterns (prohibited-practice matching, prompt injection, data
  poisoning, audit log integrity, etc.)
- **Professional+ tier required**, $99/mo (matches HIPAA/PCI convention)
- **Compliance Scan Engine integration**: Pro + EU AI Act customers
  see the new framework alongside HIPAA, PCI, ISO 42001, FedRAMP, FIPS
  in every `/api/v1/compliance/scan` report

### Compliance Scan Engine (continued from v3.2.0)

- **10th framework registered**: `eu_ai_act` joins the 9 existing
  frameworks (HIPAA, PCI, SOC 2, ISO 42001, FedRAMP, FIPS, MITRE ATLAS,
  NIST AI RMF, OWASP LLM Top 10)
- **Real control counts in scan reports**: the scanner now returns
  the actual number of controls per framework (was 0 for SOC 2, ISO,
  FedRAMP, FIPS in v3.2.0; EU AI Act ships with 82 — the first
  non-HIPAA/PCI framework with real counts)

### Test-mode Buy Buttons

All 7 module Buy Buttons + Pro + Enterprise are in **Stripe test mode**.
Beta users can simulate purchases end-to-end:

1. Visit `https://aegisgatesecurity.io/pricing/`
2. Click any Buy Button
3. Use Stripe test card `4242 4242 4242 4242` + any future expiry + any CVC
4. Webhook fires, license updates, module activates — all real, no money charged

The flip to **live mode** is scheduled for v3.4.0 once the (deferred)
paid pentest and legal review are signed off.

### Test coverage

- 95%+ on the new `pkg/compliance/eu-ai-act/` sub-package
- 100% on the registry/gating changes
- Full project test suite: 2,548+ tests passing, 0 failures
- 0 known CVEs (Trivy + Grype scanned)

### Documentation

- `docs/compliance/eu-ai-act.md` — customer 1-pager
- `plans/EU-AI-ACT-CONTROL-MAPPING.md` — internal 82-control mapping
  (the "we are experts" artifact)
- `content/pricing.md` — pricing page (test mode banner)
- `content/tech.md` — updated framework list with control counts

### Known limitations (deferred to v3.4.0+)

- **Paid external pentest** ($15-25K) — not yet commissioned
- **Paid legal counsel review** ($5-10K) — not yet commissioned
- **Public commercial launch** (live mode) — gated on pentest + legal
- **SOC 2 Type II audit** — 6-12 month engagement, pre-Series-A
- **HIPAA Business Associate Agreement (BAA)** — separate from DPA;
  first healthcare customer will trigger
- **Public status page** (BetterStack or similar) — v4.x

---

## [3.2.0] - 2026-06-05 - Compliance Modules + Trust Framework

Six billable compliance modules (HIPAA, PCI, SOC 2, ISO 42001, FedRAMP,
FIPS) as add-ons. The Compliance Scan Engine answers "is my compliance
posture good right now?" and "what modules do I need to buy?". The
Trust Framework (5th architectural pillar) adds cryptographic agent
identity and per-session trust scoring. [Full release notes](CHANGELOG.md).

---

## [3.1.0] - 2026-05-27 - Five Protocol Pillars + Response Scanning

ACP and ANP protocol security pillars added (for 5 total). Response
scanner productized with hallucination detection and redaction. 97.8%
test coverage, 5,484 tests passing. [Full release notes](CHANGELOG.md).

---

## [3.0.0] - 2026-04-12 - A2A + Trust Framework Foundation

A2A (Agent-to-Agent) protocol support. Trust Framework foundation
(attestation primitives, Ed25519/ECDSA). Multi-tenant isolation
(Professional+). Policy engine. [Full release notes](CHANGELOG.md).

---

## Earlier releases

v2.x (2025-Q3 to 2026-Q1) — HTTP proxy + MCP server + dashboard in one
binary. Apache 2.0 from day one. See [GitHub Releases](https://github.com/aegisgatesecurity/aegisgate-platform/releases)
for the full history.
