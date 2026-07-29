# AegisGate Trust Framework (1-pager)

**Status:** v3.5.0 (shipped 2026-07-24, security hardening)  
**Last reviewed:** 2026-07-21  
**Audience:** AegisGate customers evaluating trust/identity/governance for AI agents, regulated-industry procurement teams (banking, healthcare, government), and AegisGate sales engineers answering "how does AegisGate handle AI agent trust?" questions.

This document is a 1-page summary. The full technical architecture is documented internally (Section 2.6 (10 STRIDE threats, CVSS 8.5–9.0, 7 mitigation mappings). The Go implementation lives in `pkg/trust/` + `pkg/attestation/` + `pkg/digest/` (8 packages, ~8,500 LOC, 548 tests, 85–91% coverage per package).

---

## What is the Trust Framework?

The Trust Framework is the **6th pillar** of AegisGate's 6-pillar coverage. It answers the question every regulated industry asks about AI agents: **"Who is this agent, what is it allowed to do, and can I trust what it just did?"**

The Trust Framework is the missing layer in most "AI security" tools. They scan messages for prompt injection, PII, and secrets — but they treat the agent itself as anonymous. The Trust Framework gives the agent a **cryptographic identity**, an explicit **capability contract** (what tools it's allowed to invoke, what data it can read, what delegation it can perform), a **real-time trust score** based on observed behavior, and **cryptographically signed attestations** that prove the agent's behavior to auditors.

This is the same idea as X.509 certificates for HTTPS — but for AI agents, with real-time trust scoring on top of identity.

## The 4 Components

| Component | What it does | Package | Test count |
|-----------|--------------|---------|------------|
| **Agent Identity** | Each agent gets a unique ID + ECDSA P-256 keypair. Public key registered in a tamper-evident identity registry. | `pkg/trust/identity/` | 89 tests |
| **Capability Contracts** | Signed JSON documents that declare what an agent is allowed to do (tool calls, data access, agent delegation). Enforced at request time, fail-closed. | `pkg/trust/contract/` | 67 tests |
| **Trust Score Engine** | Real-time per-agent score (0–100) based on 4 weighted factors: contract compliance (40%), behavioral anomaly (30%), historical incidents (20%), capability drift (10%). Three verdicts: TRUSTED, SUSPICIOUS, BLOCKED. | `pkg/trust/score/` | 198 tests |
| **Signed Attestations** | ECDSA-signed JSON envelopes (using the `pkg/attestation/` primitive) that prove to auditors: "agent X was at score 87.5 with these factors at this time." The auditor verifies the signature against the platform's public key, no server round-trip needed. | `pkg/attestation/` + `pkg/trust/attestation/` | 156 tests |

## Why this matters for regulated industries

### Banking (SOC 2 + ISO 42001)
Auditors ask: "Show me the access log proving that the agent that processed this loan application was authorized for that customer, and show me the trust score it had at the time." The Trust Framework answers both: capability contracts prove authorization, signed attestations prove the trust score with cryptographic integrity.

### Healthcare (HIPAA)
A hospital's AI agent processing patient data needs to prove it had PHI access authorization at the time of access. The AegisGate Trust Framework's signed attestations are tamper-evident and include the agent's trust score, the capability contract version, and the timestamp. This is the **minimum viable evidence package** for HIPAA audit.

### Government / FedRAMP (Path B)
Federal agencies require non-repudiation: who did what, when, with what authority, and how do I prove it? The Trust Framework's signed attestations + the IOC store's hash chain (pkg/ioc/) together provide a complete audit trail.

### EU AI Act (Art 9 risk management, Art 14 human oversight)
The EU AI Act's `eu-ai-act.md` 1-pager notes that the AegisGate platform is **complementary** to a Notified Body. The Trust Framework provides the cryptographic evidence that the customer's risk-management system can present to the Notified Body.

## What's enforced vs. recommended

- **Enforced at runtime** (capability contracts + trust score):
  - Every tool call is checked against the agent's capability contract (fail-closed if unauthorized)
  - Every tool call updates the trust score (penalty for high-risk actions, anomaly for unexpected patterns)
  - Score drops below threshold (50) → agent is automatically blocked pending human review
  - Score drops to 0-49 (BLOCKED) → all operations rejected
- **Recommended for compliance evidence** (signed attestations + dashboard):
  - AegisGate generates the signed attestations; the customer's compliance team or auditor verifies and archives them
  - Real-time agent map dashboard shows all agents + scores + recent activity (for SOC dashboards)
  - CISO Posture Digest (`pkg/digest/`) generates a weekly PDF report with trust score trends

## Customer-facing API

The Trust Framework exposes a customer-portal HTTP API at `/api/v1/trust/*`:

| Endpoint | What it returns | Auth |
|----------|-----------------|------|
| `GET /api/v1/trust/score?agent=ID` | Lifetime trust score for an agent | License (Professional+) |
| `GET /api/v1/trust/score?session=ID` | Current session score | License (Professional+) |
| `GET /api/v1/trust/sessions?active=true&agent=ID` | Active sessions | License (Professional+) |
| `GET /api/v1/trust/attestations?agent=ID&since=TS` | Signed attestations since timestamp | License (Professional+) |
| `GET /api/v1/trust/attestations/latest?agent=ID` | Most recent attestation | License (Professional+) |
| `GET /api/v1/trust/health` | Liveness check | Public |

Every attestation response is **self-verifying** — the response includes the platform's public key, the signed payload, and the signature. An auditor can verify the signature using only the public key, with no server round-trip required.

## Tier & pricing

- **Tier required:** Professional+ (Professional $499/mo, Enterprise $2,000/mo)
- **Pricing model:** **included in the tier** — not a separately-billable module (locked decision 2026-06-04). The Trust Framework is a platform capability, not a compliance add-on. Customers who want deeper trust-score analytics than the tier provides can negotiate custom Enterprise SLAs.

To enable: set `trust.enabled: true` in `configs/aegisgate-platform.yaml` (or `AEGISGATE_TRUST_ENABLED=true` env var). When `trust.require_license: true` (default), the API is gated behind Professional+ via `pkg/license.LicenseMiddleware`.

## Self-attested, not third-party validated

> The Trust Framework's cryptographic primitives are **standardized** (ECDSA P-256 = FIPS 186-4, NIST P-256, used in TLS 1.3 and JWT ES256). The envelope format is **internally specified** (`pkg/attestation/`, frozen 2026-06-15 by Council of Mine unanimous Devil's Advocate vote). The Trust Framework is **self-attested** for the AegisGate-specific trust-score algorithm and the "TRUSTED/SUSPICIOUS/BLOCKED" thresholds. Customers should consult qualified counsel or a Notified Body for opinion-of-counsel on the suitability of AegisGate's trust scoring for their specific compliance program.

## What AegisGate does NOT cover (out of scope)

- **Notary / conformity assessment.** AegisGate is a security gateway, not a Notified Body.
- **Background checks on agent developers.** We verify the agent's identity (cryptographic keypair), not the human's identity behind the agent.
- **AI model risk scoring.** The Trust Framework scores the *agent* (behavior, contracts), not the underlying LLM model. Model risk is the customer's responsibility (separate from agent risk).
- **Federated trust across organizations.** v3.4.0+ is single-organization. Cross-org trust federation is on the v4.0+ roadmap (Sprint 17+).
- **PKI / certificate authority integration.** AegisGate generates its own ECDSA keypairs. Integration with enterprise PKI (HashiCorp Vault, Microsoft AD CS) is on the Enterprise+ roadmap.

## Linkage to other AegisGate modules

- **IOC Library + Trust Framework**: the IOC store (`pkg/ioc/`, federated IOCs) records every detection across all instances. The Trust Framework's per-agent scores are correlated against IOC matches — a sudden spike in IOCs for an agent's recent calls causes the score to drop faster.
- **Compliance modules (HIPAA, SOC 2, EU AI Act)**: each compliance scan report can include the relevant trust score for the agent that triggered the report. The auditor gets "this SOC 2 control failed because agent X (score 67) attempted Y" instead of "agent Y did Z."
- **A2A + ACP protocols**: every agent-to-agent message carries a trust score header (`X-AegisGate-Trust-Score: 87.5`) so the receiving agent can make decisions based on the sender's trust. This is the natural progression from "trust this agent's identity" to "trust this agent's current behavior."

## Versioning

| AegisGate version | Trust Framework status |
|-------------------|------------------------|
| v3.0.0 and earlier | Not present (HTTP/MCP/A2A/RESPONSE only — 4 pillars) |
| v3.1.0 / v3.2.0 | Trust packages pre-built (~8,500 LOC, 548 tests) but not first-class |
| v3.3.0 | Trust packages available as opt-in; not yet wired in main.go |
| **v3.5.0** (current) | **Trust Framework promoted to 6th pillar; HTTP API at `/api/v1/trust/*`; tier-gated to Professional+ per locked decision Q3** |
| v4.0+ (planned) | Cross-organization trust federation; PKI integration; ML-based anomaly detection (the v4.x ML tier) |

## References

- Threat model: internal document Section 2.6 (10 STRIDE threats, 7 mitigation mappings)
- Envelope primitive: `pkg/attestation/attestation.go` (frozen 2026-06-15, ECDSA P-256)
- Customer explainer for IOC federation: `docs/federated-ioc-library.md`
- Customer explainer for EU AI Act: `docs/compliance/eu-ai-act.md` (Art 9 + Art 14 reference the Trust Framework)
- Pricing: https://aegisgatesecurity.io/pricing/ (Professional+ tier, no separate Trust module cost)

---

*Document version: 1.0*  
*Last updated: 2026-07-21*  
*AegisGate Platform v3.5.0*
