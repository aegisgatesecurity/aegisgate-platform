# AegisGate Technical Architecture

> **Source of truth** for the aegisgatesecurity.io technical architecture
> page. The static site at `docs/website/index.html` mirrors this content;
> when this file changes, the static site is regenerated.
>
> Last updated: 2026-06-06 (v3.3.0 — EU AI Act module)
> Architecture decisions: see the internal roadmap and the
> `aegisgate-v3.2.0-locked-decisions` decision log.

---

## Overview

AegisGate is a **single binary** (14MB compressed, 19.1MB Docker image)
that runs three services on three ports:

| Port  | Service                | Protocol                |
|-------|------------------------|-------------------------|
| 8080  | HTTP proxy             | OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, Cohere |
| 8081  | MCP server             | Model Context Protocol  |
| 8443  | Admin dashboard + API  | HTTPS (auto-TLS via built-in CA) |

No separate deployments. No configuration drift. Apache 2.0 licensed.

---

## Five Protocol Pillars

| # | Pillar | Package | Status |
|---|--------|---------|--------|
| 1 | **HTTP API** | `pkg/proxy/` | ✅ from v2.0.1 |
| 2 | **MCP** (Model Context Protocol) | `pkg/mcpserver/` | ✅ from v2.0.1 |
| 3 | **A2A** (Agent-to-Agent) | `pkg/a2a/` | ✅ from v3.0.0 |
| 4 | **ACP** (Agent Communication Protocol) | `pkg/acp/` | ✅ from v3.1.0 |
| 5 | **ANP** (Agent Network Protocol) | `pkg/anp/` | ✅ from v3.1.0 |

Plus the **Trust Framework** pillar (cryptographic agent identity,
per-session trust scoring, signed attestations) — Professional+ tier
(added in v3.2.0 Phase 4).

---

## Compliance Frameworks (10 total — v3.3.0)

The Compliance Scan Engine (introduced in v3.2.0 Phase 3) evaluates
each customer request against all enabled frameworks. **3 frameworks
are always free** (Community tier mandate); **7 are billable modules**.

### Free (Community tier — always)

| Framework | Controls | Package |
|-----------|---------:|---------|
| MITRE ATLAS | 66 techniques | `pkg/compliance/atlas/` |
| NIST AI RMF 1.0 | 4 functions (GV/MA/MS/RG) | `pkg/compliance/nist_ai_rmf/` |
| OWASP LLM Top 10 | 10 risks | `pkg/compliance/owasp/` |

### Billable modules (paid tier add-ons)

| Module | Controls | Required Tier | Price | Package |
|--------|---------:|---------------|------:|---------|
| HIPAA | 13 | Developer+ | $99/mo | `pkg/compliance/hipaa/` |
| PCI-DSS | 21 | Developer+ | $99/mo | `pkg/compliance/pci/` |
| SOC 2 | — (in roadmap) | Developer+ | $149/mo | `pkg/compliance/soc2/` (TBD) |
| ISO 42001 | — (in roadmap) | Professional+ | $79/mo | `pkg/compliance/iso42001/` (TBD) |
| FedRAMP | — (in roadmap) | Professional+ | $499/mo | `pkg/compliance/fedramp/` (TBD) |
| FIPS 140-2/140-3 | — (in roadmap) | Professional+ | $299/mo | `pkg/compliance/fips/` (TBD) |
| **EU AI Act** 🆕 | **82** | **Professional+** | **$99/mo** | `pkg/compliance/eu-ai-act/` |

> The 4 roadmap modules (SOC 2, ISO 42001, FedRAMP, FIPS) ship as
> *billable + registered* (the buy button works) but their sub-package
> implementations return 0 controls until their v3.4.0+ build-out. The
> EU AI Act module is the **first to ship fully implemented** in v3.3.0.

### 🆕 EU AI Act coverage (v3.3.0)

**82 controls** across 8 categories spanning Articles 5, 9, 10, 11,
12, 13, 14, 15, 51-55 of Regulation (EU) 2024/1689, plus 10
AegisGate-specific AI extensions:

| Category | Controls | Articles |
|----------|---------:|----------|
| Prohibited Practices | 8 | Art 5 |
| Risk Management | 10 | Art 9 |
| Data Governance | 8 | Art 10 |
| Technical Documentation + Record Keeping | 10 | Art 11 + 12 |
| Transparency + Human Oversight | 14 | Art 13 + 14 |
| Accuracy, Robustness, Cybersecurity | 12 | Art 15 |
| GPAI Models | 10 | Art 51-55 |
| AegisGate AI Extensions | 10 | (proprietary) |

**9 of 82 controls are automated** via AegisGate's detection
patterns (e.g., prohibited-practice pattern matching, prompt injection
detection, data poisoning scanning, audit log integrity checks). The
remaining 73 are manual review items for the customer's compliance
team — this 91/9 split mirrors the HIPAA sub-package's approach.

---

## Detection Capabilities (always free, Community tier)

- **144+ prompt-injection patterns** (HTTP, MCP, A2A, ACP, ANP)
- **44-regex secret detection** (AWS keys, GitHub tokens, JWTs, private keys, etc.)
- **PII detection** (GDPR view: emails, phone numbers, SSNs, credit cards, IBANs)
- **Toxicity + hallucination detection** on AI responses
- **MITRE ATLAS** (66 techniques covered, 55% of full taxonomy)
- **NIST AI RMF 1.0** (Govern, Map, Measure, Manage functions)
- **OWASP LLM Top 10** (prompt injection, insecure output handling, training data
  poisoning, model DoS, supply chain vulnerabilities, sensitive info disclosure,
  insecure plugin design, excessive agency, overreliance, model theft)

---

## Performance

- **11,681 peak RPS** (k6 load test)
- **2.44ms average latency** at 1K RPS
- **19.1MB Docker image** (distroless)
- **2,548 tests passing** (97.7% coverage)
- **0 known CVEs** (Trivy + Grype scanned)

---

## Self-Hosted

- **Single binary** (`aegisgate-v2`) — no external services required for Community
- **Storage backends**: file (Community), SQLite/Redis (Developer+),
  PostgreSQL/S3 (Professional+), MongoDB (Enterprise)
- **Deployment**: Docker, Docker Compose, Terraform, Kubernetes + Helm
- **Air-gapped mode**: Enterprise tier (offline install + FIPS-validated crypto)

---

## Open Source

- **License:** Apache 2.0
- **Repository:** https://github.com/aegisgatesecurity/aegisgate-platform
- **SBOM:** CycloneDX format, auto-generated per release
- **Signed releases:** cosign + GPG, verified via GitHub OIDC
