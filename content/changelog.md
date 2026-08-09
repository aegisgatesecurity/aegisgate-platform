# AegisGate Changelog

> **Source of truth** for the aegisgatesecurity.io changelog page. The
> static site at `docs/website/index.html` mirrors this content.
>
> For the full engineering changelog (per-commit, per-PR detail), see
> `CHANGELOG.md` in the platform repository.
>
> Last updated: 2026-08-01 (v3.6.0 — Security Hardening, ML Pipeline, ATLAS FPR Fix)

---

## [3.6.0] - 2026-08-01 - Security Hardening, ML Pipeline, ATLAS FPR Fix 🔒

> **v3.6.0** is a hard version rebaseline: ATLAS false-positive rate eliminated (30.8%→0.0%), evasion-resistant detection normalization, ML pipeline foundation for v4, rule integrity verification, and 70% proxy overhead reduction.

### Security Hardening

- **P0/P1 bug fixes** across scanner, proxy, and compliance engine — content extraction, token smuggling regex, ATLAS over-matching
- **ATLAS FPR 30.8%→0.0%** — 16 context-aware pattern refinements; zero false positives on the ATLAS benchmark suite
- **Unicode homoglyph language detection** — catches confusable-script attacks (Cyrillic, Greek, Armenian) while preserving multilingual input

### Performance

- **70% proxy overhead reduction** — request processing pipeline re-architected for throughput
- 24,806 peak RPS sustained on benchmark hardware

### Detection & Evasion Resistance

- **Evasion-resistant normalization pipeline** — sliding ROT13, aggressive repeating-char collapse, Unicode canonicalization (+4.7 pts evasion score)
- **Multi-turn attack detection** — conversation-level attack pattern recognition across request sequences
- **Aggressive repeating-char detection** — catches `iiiiii` and `!!!!` style evasion padding (+1.8 pts)
- **Sliding ROT13 detection** — catches `Ebg13` and `Ceboyrz` style obfuscation

### ML Pipeline (v4 Foundation)

- **Char CNN-BiLSTM data pipeline** — detector, calibrator, and normalizer for ML-based threat detection
- **Benign corpus: 10,000+ examples** across 15 categories for training and calibration
- **ML feature flags** — `AEGIS_ML_THREAT_DETECTION_ENABLED` and `AEGIS_ML_SHADOW_MODE` for cold-start deployment
- **Graceful degradation** — rules-only mode with 0% FPR guarantee; shadow mode for safe ML validation

### Compliance

- **ATLAS playbooks: 10 new playbooks** (66→76 technique coverage with context)
- **Rule integrity verification** — SHA256 hash endpoint at `GET /api/v1/compliance/integrity` for audit verification
- **MTTI auto-enrichment** — 52 ATLAS sub-techniques auto-mapped to detection rules with severity and recommended response

### Quality

- 55 packages passing, 0 failures, 0 race conditions
- Docker image: 34.7MB, Alpine-based, non-root, FIPS-ready

---

## [3.5.0] - 2026-07-28 - Compliance Engine v2, gRPC, Trust API, SIEM, SSO Persistence 🏛️

> **v3.5.0** is a major feature release: FedRAMP automation from 82→151 controls (88.8%), gRPC service layer with 50 RPCs, Trust API attestation, SIEM promotion, SSO PostgreSQL persistence, token analytics, and PDF export.

### Highlights

- **FedRAMP 151/170 automated (88.8%)** — 69 controls promoted from manual/stub to real CheckFuncs. 19 remaining are genuinely customer-responsibility (policy-only, HR, physical security).
- **gRPC service layer** — 7 services, 50 RPCs, health checking, reflection, TLS.
- **Trust API attestation** — Cryptographic attestation with RFC 3161 TSA timestamping.
- **SIEM promotion** — Real event forwarding to Splunk/Datadog/ELK.
- **SSO PostgreSQL persistence** — Sessions survive restarts. ACR value mapping for OIDC.
- **Token analytics** — Per-request usage metrics wired into the pipeline.
- **PDF export** — Questionnaire results to formatted PDF with scoring and evidence.

### Breaking Changes

- Starter tier removed from billing. Community is free, Developer ($79/mo) is first paid tier.

---

## [3.4.3] - 2026-07-24 - Security Hardening 🔐

> **v3.4.3** fixes critical auth bypass issues found during pre-ship adversarial
> testing. 5 endpoints were accessible without authentication; all are now
> wrapped with `RequireAuth()`. `/metrics` is restricted to localhost. CSP
> is hardened (`unsafe-eval` removed). 26/27 manual red team tests pass (superseded by automated 2,600-test evasion suite in v4.0.0: 100/100 with ML).

### Security Fixes

- **🔴 CRITICAL:** IOC Admin API endpoints mounted without auth → now RequireAuth() + admin tier
- **🔴:** `/metrics` exposed system internals → now localhost-only
- **🟡:** `/cluster/health`, `/bridge`, `/guardrails`, `/policies` returned data without auth → now RequireAuth()
- **🟡:** CSP `unsafe-eval` removed from dashboard, `unsafe-inline` removed from API

### Metrics (v3.5.0)

- 2,454 tests passing, 87.4% coverage, 99 packages
- 24K+ RPS, 0 CVEs, 153 detection patterns
- 15+ compliance frameworks, HA clustering support

---

## [3.4.2] - 2026-07-24 - HA Clustering & Break Testing 🏗️

> **v3.4.2** adds horizontal scaling with distributed rate limiting, instance identity,
> and cluster health monitoring. Break-tested at 20x baseline load (0% errors).

### Highlights

- HA clustering with distributed rate limiting (Professional+)
- Instance identity headers (`X-Instance-Id`, `X-Cluster-Mode`)
- Cluster health endpoint with node topology
- 22 pkg/cluster tests, 56.5% coverage (PG-dependent paths exempted)
- Break test: 0% errors at 20x baseline (2,000 VU, 24K+ RPS)

---

## [3.4.1] - 2026-07-24 - OPSEC Remediation & Compliance Expansion 🔒

> **v3.4.1** fixes a critical 503 health-check regression, hardens the repository
> against credential leaks, and includes CMMC L2 compliance expansion.

### Highlights

- Fix 503 health-check regression on Community tier
- CMMC Level 2 compliance module (14 controls)
- OPSEC cleanup: removed leaked credentials, scrubbed history
- NIST 800-171, HITRUST, TISAX, ISO 27001 compliance modules

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
- EU AI Act control mapping (internal) — 82-control mapping
  (the "we are experts" artifact)
- [Pricing page](https://aegisgatesecurity.io/pricing/) — pricing page (test mode banner)
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
