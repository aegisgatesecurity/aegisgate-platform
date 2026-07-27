<div align="center">

# 🛡️ AegisGate Security Platform

**Secure every AI interaction. Six pillars. One gateway. Zero external dependencies.**

[![Version](https://img.shields.io/badge/Version-v3.4.3-blue?logo=semver)](https://github.com/aegisgatesecurity/aegisgate-platform/releases/tag/v3.4.3)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26.5-00ADD8?logo=go)](https://golang.org/)
[![Tests](https://img.shields.io/badge/Tests-2454_passing-brightgreen?logo=checkmarx)](https://github.com/aegisgatesecurity/aegisgate-platform/actions)
[![Coverage](https://img.shields.io/badge/Coverage-87.4%25-green?logo=codecov)](https://github.com/aegisgatesecurity/aegisgate-platform/actions)
[![EU AI Act](https://img.shields.io/badge/EU_AI_Act-82_controls-003399?logo=europeanunion)](docs/compliance/eu-ai-act.md)
[![Lens](https://img.shields.io/badge/Lens-153_patterns-38bdf8?logo=googleslides&logoColor=white)](https://github.com/aegisgatesecurity/aegisgate-lens)

[🌐 Website](https://aegisgatesecurity.io) · [🚀 Live Demo](https://demo.aegisgatesecurity.io/) · [📊 Pricing](https://aegisgatesecurity.io/pricing/) · [📚 Docs](https://aegisgatesecurity.io/docs/) · [🔒 Security](SECURITY.md) · [💬 Discussions](https://github.com/aegisgatesecurity/aegisgate-platform/discussions)

</div>

---

## What is AegisGate?

AegisGate is the only AI security platform with **6 native protection pillars** — HTTP API, MCP, A2A, ACP, RESPONSE, and Trust Framework — in a single binary with zero external dependencies. Security hardening and red team verification ensure production-grade resilience.

## v3.4.3 Highlights

| Feature | Description |
|---------|-------------|
| **153-Pattern Detection Engine** | Full Lens parity: 45 secrets, 12 XSS, 15+13+9+24 PII, 35 compliance patterns |
| **PostgreSQL Persistence** | 6 integration test suites (107 tests) via testcontainers-go |
| **150 FedRAMP Controls** | NIST 800-53 Moderate baseline with cross-framework traceability |
| **5 Compliance Modules** | CMMC L2, NIST 800-171, HITRUST, TISAX, ISO 27001 |
| **Incident Response** | Automated detection rules, playbooks, compliance mapping |
| **SOC 2 Audit** | Evidence collection, policy templates, workpapers |
| **SSE Streaming** | Real-time SOC incident timeline |
| **Multi-Tenant Isolation** | `tenant_id` across 4 packages with migration 004 |
| **HA Clustering** | Multi-node deployments with distributed rate limiting, instance identity, and health checks |
| **Security Hardening** | 5 auth bypass fixes, localhost-only metrics, CSP hardening. 26/27 red team tests pass |

## Why AegisGate?

Every AI interaction is an attack surface. Prompt injections leak secrets. MCP servers exfiltrate context. A2A agents escalate privileges across trust boundaries. A single misconfigured LLM response can expose PII, violate compliance, or hand an attacker a credential.

AegisGate sits in front of all of it — one binary, zero dependencies, fail-closed by default.

- **Sub-millisecond overhead.** 3.2ms p95 at 24K+ RPS. Your users won't notice it's there.
- **Fail-closed.** If AegisGate can't scan a response, it blocks it. No silent failures, no pass-through on error.
- **Self-hosted.** No API keys to rotate, no third-party to trust. Your data stays in your infrastructure.
- **6 pillars, one gateway.** HTTP, MCP, A2A, ACP, RESPONSE, and Trust — no patchwork of point products.
- **153 detection patterns.** Secrets, XSS, PII, and compliance — wired into every response, every time.
- **Red-team hardened.** 26/27 adversarial tests pass. TRACE methods rejected. All security headers present. No `unsafe-eval` in CSP.

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

## Detection Engine

The `pkg/response/detectors/` package provides 153 regex patterns with full Lens parity:

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
| FedRAMP (NIST 800-53) | 150 | `pkg/compliance/fedramp/` |
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

[🌐 AegisGate Security](https://aegisgatesecurity.io) · [✉️ support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io)

Made with ❤️ by AegisGate Security developers to secure the AI attack surface.

</div>