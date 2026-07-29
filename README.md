<div align="center">

# 🛡️ AegisGate Security Platform

**Secure every AI interaction. Six pillars. One gateway. Zero external dependencies.**

[![Version](https://img.shields.io/badge/Version-v3.5.0-blue?logo=semver)](https://github.com/aegisgatesecurity/aegisgate-platform/releases/tag/v3.5.0)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26.5-00ADD8?logo=go)](https://golang.org/)
[![Tests](https://img.shields.io/badge/Tests-2454_passing-brightgreen?logo=checkmarx)](https://github.com/aegisgatesecurity/aegisgate-platform/actions)
[![Coverage](https://img.shields.io/badge/Coverage-87.4%25-green?logo=codecov)](https://github.com/aegisgatesecurity/aegisgate-platform/actions)
[![EU AI Act](https://img.shields.io/badge/EU_AI_Act-82_controls-003399?logo=europeanunion)](docs/compliance/eu-ai-act.md)
[![Lens](https://img.shields.io/badge/Lens-153_patterns-38bdf8?logo=googleslides&logoColor=white)](https://github.com/aegisgatesecurity/aegisgate-lens)

[🌐 Website](https://aegisgatesecurity.io) · [🚀 Live Demo](https://demo.aegisgatesecurity.io/) · [📊 Pricing](https://aegisgatesecurity.io/pricing/) · [📚 Docs](https://aegisgatesecurity.io/docs/) · [🔒 Security](SECURITY.md) · [💬 Discussions](https://github.com/aegisgatesecurity/aegisgate-platform/discussions)

</div>

---

> **🧩 Using AI without enterprise protections?** [AegisGate Lens](https://github.com/aegisgatesecurity/aegisgate-lens) is our free browser extension that brings 153 detection patterns to everyday AI conversations — for the 95% of users who don't have a security gateway. [Install Lens →](https://github.com/aegisgatesecurity/aegisgate-lens)

---

## Why AegisGate?

Every AI interaction is an attack surface. Prompt injections leak secrets. MCP servers exfiltrate context. A2A agents escalate privileges across trust boundaries. A single misconfigured LLM response can expose PII, violate compliance, or hand an attacker a credential.

AegisGate sits in front of all of it — one binary, zero dependencies, fail-closed by default.

- **Sub-millisecond overhead.** 3.2ms p95 at 24K+ RPS. Your users won't notice it's there.
- **Fail-closed.** If AegisGate can't scan a response, it blocks it. No silent failures, no pass-through on error.
- **Self-hosted.** No API keys to rotate, no third-party to trust. Your data stays in your infrastructure.
- **6 pillars, one gateway.** HTTP, MCP, A2A, ACP, RESPONSE, and Trust — no patchwork of point products.
- **153 detection patterns.** Secrets, XSS, PII, and compliance — wired into every response, every time.
- **Red-team hardened.** 26/27 adversarial tests pass. TRACE methods rejected. All security headers present. No `unsafe-eval` in CSP.

## Security Posture

| Metric | Value |
|--------|-------|
| CVEs | **0** |
| Red team tests passed | **26 / 27** |
| Fail-closed by default | ✅ |
| TRACE/CONNECT/TRACK blocked | ✅ |
| Security headers (CSP, CORP, COEP, COOP, HSTS) | ✅ |
| Private keys in git | **0** (rotated, gitignored, pre-commit blocked) |
| Code-scanning alerts open | **0** |
| Dependabot alerts open | **0** |

## Request Flow

```mermaid
flowchart LR
    Client["👤 Client / Agent"] -->|"HTTP · MCP · A2A"| Gateway["🛡️ AegisGate"]

    subgraph Pillars["6 Protection Pillars"]
        direction TB
        HTTP["HTTP API<br/>pkg/response/"]
        MCP["MCP<br/>pkg/mcpserver/"]
        A2A["A2A<br/>pkg/a2a/"]
        ACP["ACP<br/>pkg/acp/"]
        RESP["RESPONSE<br/>pkg/response/detectors/"]
        TRUST["Trust<br/>pkg/attestation/"]
    end

    Gateway --> Pillars
    Pillars -->|"Scanned ✅"| LLM["🤖 LLM / AI Service"]
    Pillars -->|"Blocked ❌"| Client

    LLM -->|"Response"| Gateway
    Gateway -->|"Clean"| Client
    Gateway -->|"Sanitized / Rejected"| Client

    subgraph Infra["Infrastructure"]
        PG[("PostgreSQL<br/>persistence")]
        Redis[("Redis<br/>rate limiting")]
    end

    Gateway --- Infra
```

## Detection Engine

The `pkg/response/detectors/` package provides 153 regex patterns with full Lens parity:

| Category | Patterns | What it catches |
|----------|----------|-----------------|
| **Secrets** | 45 | AWS keys, GitHub PATs, Stripe keys, JWTs, GitLab tokens, Twilio, SendGrid, private keys |
| **XSS** | 12 | `<script>`, event handlers, `javascript:`, SVG-based, encoded variants |
| **PII (US Core)** | 15 | SSN, phone, DOB, MRN, ZIP+4, full names with context |
| **PII (Extended)** | 13 | Email, IP addresses, passport numbers, driver's licenses |
| **PII (International)** | 9 | National IDs (NHS, SIN, TFN, IRD, BSN, CF, SSN-IT, NRIC, MyNumber) |
| **PII (Financial)** | 24 | Credit cards, IBANs, SWIFT/BIC, routing numbers |
| **Compliance** | 35 | GDPR data types, HIPAA PHI indicators, PCI-DSS card data, CCPA personal info |

```go
import "github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors"

// Scan all 153 patterns
matches := detectors.DetectAll(text)

// Scan by category
secrets := detectors.DetectSecrets(text)
xss := detectors.DetectXSS(text)
pii := detectors.DetectPIIUSCore(text)
compliance := detectors.DetectCompliance(text)

// Wired into ResponseGuard (default: enabled)
guard := response.NewResponseGuard()
result, _ := guard.Scan(ctx, text)
// result.DetectedXSS, result.DetectedCompliance, result.DetectedPII, result.DetectedSecrets
```

## How AegisGate Compares

| Capability | AegisGate | Generic AI Firewalls |
|------------|-----------|----------------------|
| HTTP API scanning | ✅ Native | ✅ |
| MCP guardrails | ✅ Native | ❌ Plugin or missing |
| A2A protocol security | ✅ Native | ❌ Not supported |
| ACP enforcement | ✅ Native | ❌ Not supported |
| Response scanning (153 patterns) | ✅ Built-in | ⚠️ Limited or external |
| Cryptographic attestation | ✅ Native | ❌ Not available |
| Self-hosted, zero dependencies | ✅ Single binary | ❌ Requires external services |
| Fail-closed by default | ✅ | ⚠️ Often fail-open |
| 15+ compliance frameworks | ✅ | ⚠️ 3–5 typical |
| PostgreSQL + file persistence | ✅ | ⚠️ Cloud-locked |
| HA clustering | ✅ Native | ⚠️ Enterprise add-on |
| Open source (Apache 2.0) | ✅ | ❌ Proprietary |

## v3.5.0 Highlights

| Feature | Description |
|---------|-------------|
| **FedRAMP 151/170 Automated (88.8%)** | Compliance Engine v2: 69 controls promoted from manual/stub to real CheckFuncs. 19 remaining are customer-responsibility. |
| **gRPC Service Layer** | 7 services, 50 RPCs with health checking, reflection, and TLS |
| **Trust API Attestation** | Cryptographic attestation generation and verification (RFC 3161 TSA) |
| **SIEM Promotion** | Real event forwarding to Splunk/Datadog/ELK (no longer a stub) |
| **SSO Persistence** | PostgreSQL-backed OIDC session storage with TTL and ACR value mapping |
| **Token Analytics** | Per-request token usage metrics wired into the request pipeline |
| **PDF Export** | Questionnaire results export to formatted PDF with scoring and evidence citations |
| **153-Pattern Detection Engine** | Full Lens parity: 45 secrets, 12 XSS, 15+13+9+24 PII, 35 compliance patterns |
| **PostgreSQL Persistence** | 6 integration test suites (107 tests) via testcontainers-go |
| **HA Clustering** | Multi-node deployments with distributed rate limiting, instance identity, and health checks |
| **Security Hardening** | 5 auth bypass fixes, localhost-only metrics, CSP hardening. 26/27 red team tests pass |

## 6 Pillars

| Pillar | Package | Description |
|--------|---------|-------------|
| HTTP API | `pkg/response/` | Request/response scanning, PII redaction, secret masking |
| MCP | `pkg/mcpserver/` | Model Context Protocol guardrails |
| A2A | `pkg/a2a/` | Agent-to-Agent protocol security |
| ACP | `pkg/acp/` | Agent Capability Policy enforcement |
| RESPONSE | `pkg/response/detectors/` | 153-pattern detection (secrets, XSS, PII, compliance) |
| Trust Framework | `pkg/attestation/`, `pkg/trust/` | Cryptographic attestation, CISO posture digest |

## Compliance Coverage

| Framework | Controls | Package |
|-----------|----------|---------|
| EU AI Act | 82 | `pkg/compliance/eu-ai-act/` |
| FedRAMP (NIST 800-53) | 170 (151 automated) | `pkg/compliance/fedramp/` |
| SOC 2 Type II | 5 | `pkg/compliance/soc2/` |
| ISO 27001 | 14 | `pkg/compliance/iso27001/` |
| HITRUST CSF | 6 | `pkg/compliance/hitrust/` |
| TISAX | 7 | `pkg/compliance/tisax/` |
| CMMC Level 2 | 14 | `pkg/compliance/cmmcl2/` |
| NIST 800-171 | 14 | `pkg/compliance/nist800171/` |
| FIPS 140-2 | 11 | `pkg/compliance/fips/` |
| NIST AI RMF | 8 | `pkg/compliance/nist_ai_rmf/` |
| CCPA | 7 | `pkg/compliance/ccpa/` |
| HIPAA | 11 | `pkg/compliance/hipaa/` |
| PCI-DSS | 12 | `pkg/compliance/pci/` |

## Quick Start

```bash
# Build
go build -o aegisgate ./cmd/aegisgate-platform

# Run with defaults (in-memory stores)
./aegisgate

# Run with PostgreSQL
export DATABASE_URL="postgres://user:pass@localhost:5432/aegisgate"
./aegisgate

# Run integration tests (requires Docker)
go test -tags=integration -timeout 300s ./pkg/ioc/... ./pkg/persistence/...
```

## Architecture

```
cmd/aegisgate-platform/     # Binary entry point
pkg/
├── a2a/                    # Agent-to-Agent security
├── acp/                    # Agent Capability Policy
├── attestation/            # Cryptographic envelope (Sign/Verify/VerifyWithKey/VerifyOnline)
├── audit/soc2/             # SOC 2 evidence collection
├── compliance/             # 15+ framework modules
├── cluster/                # HA clustering & distributed rate limiting
├── correlation/            # Event correlation engine
├── cve/                    # CVE-for-AI feed
├── detectors/              # 153-pattern detection engine
├── evaluator/              # Adversarial benchmark suite
├── ioc/                    # IOC management
├── mcpserver/              # MCP guardrails
├── persistence/            # Storage backends (file + PostgreSQL)
├── rbac/                   # Role-based access control
├── response/               # 6-pillar response guard
├── trust/                  # Trust Framework (6 sub-packages)
└── testdb/                 # Shared testcontainers infrastructure
```

## Testing

```bash
# Unit tests (99 packages)
go test ./...

# Integration tests (6 PostgreSQL packages, requires Docker)
go test -tags=integration -timeout 300s ./pkg/ioc/... ./pkg/persistence/... ./pkg/rbac/... \
  ./pkg/license/... ./pkg/correlation/... ./pkg/attestation/...

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. See [govulncheck.toml](govulncheck.toml) for the GO-2026-5932 suppression (openpgp transitive, not called).

---

<div align="center">

[🌐 AegisGate Security](https://aegisgatesecurity.io) · [✉️ support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io) · [🐦 X/Twitter](https://x.com/aegisgate) · [🐘 Mastodon](https://mastodon.social/@aegisgate)

Made with 🖤 by AegisGate Security developers to secure the AI attack surface.

</div>