<div align="center">

# 🛡️ AegisGate Security Platform

**Secure every AI interaction. Six pillars. One gateway. Zero external dependencies.**

[![Version](https://img.shields.io/badge/Version-v4.1.0-blue?logo=semver)](https://github.com/aegisgatesecurity/aegisgate-platform/releases/tag/v4.1.0)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26.6-00ADD8?logo=go)](https://golang.org/)
[![Tests](https://img.shields.io/badge/Tests-8000+_passing-brightgreen?logo=checkmarx)](https://github.com/aegisgatesecurity/aegisgate-platform/actions)
[![Coverage](https://img.shields.io/badge/Coverage-83.1%25-green?logo=codecov)](https://github.com/aegisgatesecurity/aegisgate-platform/actions)
[![EU AI Act](https://img.shields.io/badge/EU_AI_Act-82_controls-003399?logo=europeanunion)](docs/compliance/eu-ai-act.md)
[![SIEM](https://img.shields.io/badge/SIEM-Pro+_only-9333ea?logo=splunk)](#tier-gated-features)
[![ML Detection](https://img.shields.io/badge/ML_Detection-Pro+_only-22c55e?logo=tensorflow)](#tier-gated-features)
[![Lens](https://img.shields.io/badge/Lens-Browser_Extension-38bdf8?logo=googleslides&logoColor=white)](https://github.com/aegisgatesecurity/aegisgate-lens)
[![CI](https://github.com/aegisgatesecurity/aegisgate-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-platform/actions/workflows/ci.yml)
[![Security](https://github.com/aegisgatesecurity/aegisgate-platform/actions/workflows/security.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-platform/actions/workflows/security.yml)
[![Security Policy](https://img.shields.io/badge/security-RFC%209116-blue.svg)](./SECURITY.md)

[🌐 Website](https://aegisgatesecurity.io) · [🚀 Live Demo](https://demo.aegisgatesecurity.io/) · [📊 Pricing](https://aegisgatesecurity.io/pricing/) · [📚 Docs](https://aegisgatesecurity.io/docs/) · [🔒 Security](SECURITY.md) · [💬 Discussions](https://github.com/aegisgatesecurity/aegisgate-platform/discussions)

</div>

> **We follow [GitHub's recommended security practices](https://securitylab.github.com/resources/five-easy-steps-to-secure-your-open-source-project/) for open source projects.** CodeQL scanning · Secret scanning with push protection · Dependabot alerts & security updates · Protected branches · RFC 9116 security policy · [Report a vulnerability →](./SECURITY.md)

---

> **🧩 Using AI without enterprise protections?** [AegisGate Lens](https://github.com/aegisgatesecurity/aegisgate-lens) is our free browser extension that brings detection patterns to everyday AI conversations — for the 95% of users who don't have a security gateway. [Install Lens →](https://github.com/aegisgatesecurity/aegisgate-lens)

---

## Open-Core Model

AegisGate is **open-core**: the community edition is Apache 2.0 open source, and enterprise features are proprietary.

| Edition | License | Features |
|---------|---------|----------|
| **Community** (free) | Apache 2.0 | HTTP/MCP/A2A/ACP/Response scanning, 153 detection patterns, 6 community compliance frameworks, in-memory + file persistence, HA clustering |
| **Developer** ($79/mo) | Proprietary | + 6 regulatory frameworks (HIPAA, PCI, SOC 2, ISO 27001, CCPA, GDPR), PostgreSQL persistence, SSO |
| **Professional** ($499/mo) | Proprietary | + 11 industry frameworks (EU AI Act, FedRAMP, NIST CSF, FIPS, CIS, SOX, etc.), Trust Framework, SIEM (11 platforms), ML threat detection, federated IOC, PostgreSQL |
| **Enterprise** (custom) | Proprietary | + 5 regulated frameworks (HITRUST, TISAX, CMMC L2, NIST 800-171, ISO 42001), HSM, FIPS mode, air-gapped, K8s clustering, custom ML, 24×7 support |

Enterprise features are gated via `//go:build enterprise` build tags and tier checks in `pkg/tier/tier.go`. The community edition compiles standalone (CGO_ENABLED=0, no ONNX Runtime) and returns clear `ErrEnterpriseOnly` / `codes.Unimplemented` responses when features above the licensed tier are invoked. See [Pricing →](https://aegisgatesecurity.io/pricing/)

## Why AegisGate?

Every AI interaction is an attack surface. Prompt injections leak secrets. MCP servers exfiltrate context. A2A agents escalate privileges across trust boundaries. A single misconfigured LLM response can expose PII, violate compliance, or hand an attacker a credential.

AegisGate sits in front of all of it — one binary, zero dependencies, fail-closed by default.

- **Zero-cost proxy.** -2.8ms p99 overhead (faster than direct). Blocked requests resolve in 7.2ms p50. 15K+ RPS with 0% errors at 2,000 VUs.
- **Fail-closed.** If AegisGate can't scan a response, it blocks it. No silent failures, no pass-through on error.
- **Self-hosted.** No API keys to rotate, no third-party to trust. Your data stays in your infrastructure.
- **6 pillars, one gateway.** HTTP, MCP, A2A, ACP, Response, and Trust — no patchwork of point products.
- **153 detection patterns.** Secrets, XSS, PII, and compliance — wired into every response, every time.
- **31 compliance frameworks.** From community basics (OWASP LLM, ATLAS, NIST AI RMF) to enterprise certifications (FedRAMP, HITRUST, TISAX, CMMC L2).

## Security Posture

| Metric | Value |
|--------|-------|
| CVEs | **0** |
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
| 31 compliance frameworks | ✅ | ⚠️ 3–5 typical |
| PostgreSQL + file persistence | ✅ | ⚠️ Cloud-locked |
| HA clustering | ✅ Native | ⚠️ Enterprise add-on |
| Open-core (Apache 2.0 community) | ✅ | ❌ Proprietary |

## Pricing Tiers

| Tier | Price | Rate Limits (Proxy/MCP) | Users / Agents | Compliance | Key Features |
|------|-------|------------------------|---------------|------------|--------------|
| **Community** | Free | Soft-throttle | 5 / 5 | 6 frameworks | HTTP/MCP/A2A scanning, 153 detection patterns, in-memory persistence |
| **Developer** | $79/mo | 1,000 / 500 RPM | 25 / 25 | 10 frameworks | + HIPAA, PCI, SOC 2, ISO 27001, CCPA, GDPR, PostgreSQL |
| **Professional** | $499/mo | 10,000 / 5,000 RPM | 100 / 100 | 26 frameworks | + EU AI Act, FedRAMP, NIST CSF, FIPS, CIS, SOX, Trust Framework, SIEM (11 platforms), ML threat detection |
| **Enterprise** | Custom | Unlimited | Unlimited | 31 frameworks | + HITRUST, TISAX, CMMC L2, HSM, FIPS mode, air-gapped, K8s clustering, custom ML |

### Vertical Bundles

| Bundle | Target | Frameworks Included |
|--------|--------|-------------------|
| Healthcare | HIPAA-covered entities | HIPAA, HITECH, HITRUST, FedRAMP |
| Defense | DoD/defense contractors | CMMC L2, NIST 800-171, FedRAMP, TISAX |
| Finance | Financial services | PCI-DSS, SOX, GLBA, FFIEC, ISO 27001 |
| Privacy | Privacy-focused orgs | GDPR, CCPA, ISO 27001, EU AI Act |
| Energy | Energy/critical infra | NERC CIP, ISO 27001, NIST CSF |
| SaaS B2B | SaaS providers | SOC 2, ISO 27001, CSA STAR, CCPA |
| EU Compliance | EU organizations | EU AI Act, GDPR, ISO 27001, TISAX |

See [Pricing →](https://aegisgatesecurity.io/pricing/) for full details.

## 6 Pillars

| Pillar | Package | Description |
|--------|---------|-------------|
| HTTP API | `pkg/response/` | Request/response scanning, PII redaction, secret masking |
| MCP | `pkg/mcpserver/` | Model Context Protocol guardrails |
| A2A | `pkg/a2a/` | Agent-to-Agent protocol security |
| ACP | `pkg/acp/` | Agent Capability Policy enforcement |
| Response | `pkg/response/detectors/` | 153-pattern detection (secrets, XSS, PII, compliance) |
| Trust Framework | `pkg/attestation/` | Cryptographic attestation, CISO posture digest (Professional+: full trust scoring) |

## Compliance Coverage (31 Frameworks)

| Framework | Tier | Package |
|-----------|------|---------|
| OWASP LLM Top 10 | Community | `pkg/compliance/community/owasp/` |
| MITRE ATLAS | Community | `pkg/compliance/community/atlas/` |
| NIST AI RMF | Community | `pkg/compliance/nist_ai_rmf/` |
| OWASP Web | Community | `pkg/compliance/owasp_web/` |
| GDPR | Developer | `pkg/compliance/community/gdpr/` |
| HIPAA | Developer | `pkg/compliance/hipaa/` |
| PCI-DSS | Developer | `pkg/compliance/pci/` |
| SOC 2 Type II | Developer | `pkg/compliance/soc2/` |
| ISO 27001 | Developer | `pkg/compliance/iso27001/` |
| CCPA | Developer | `pkg/compliance/ccpa/` |
| EU AI Act | Professional | `pkg/compliance/eu-ai-act/` |
| FedRAMP (NIST 800-53) | Professional | `pkg/compliance/fedramp/` |
| NIST CSF | Professional | `pkg/compliance/nist_csf/` |
| NIST 800-171 | Professional | `pkg/compliance/nist800171/` |
| FIPS 140-2 | Professional | `pkg/compliance/fips/` |
| CIS Controls | Professional | `pkg/compliance/cis/` |
| CSA STAR | Professional | `pkg/compliance/csa_star/` |
| NIST AI 600-1 | Professional | `pkg/compliance/nist_ai_600_1/` |
| SOX | Professional | `pkg/compliance/sox/` |
| GLBA | Professional | `pkg/compliance/glba/` |
| NERC CIP | Professional | `pkg/compliance/nerc_cip/` |
| CJIS | Professional | `pkg/compliance/cjis/` |
| FERPA | Professional | `pkg/compliance/ferpa/` |
| HITECH | Professional | `pkg/compliance/hitech/` |
| FFIEC | Professional | `pkg/compliance/ffiec/` |
| TSA SD | Professional | `pkg/compliance/tsa_sd/` |
| ISO 21434 | Professional | `pkg/compliance/iso21434/` |
| ISO 42001 | Professional | `pkg/compliance/iso42001/` |
| CMMC Level 2 | Enterprise | `pkg/compliance/cmmcl2/` |
| HITRUST CSF | Enterprise | `pkg/compliance/hitrust/` |
| TISAX | Enterprise | `pkg/compliance/tisax/` |

## Tier-Gated Features

The following features are gated by tier in `pkg/tier/tier.go`. Community edition
returns clear `ErrEnterpriseOnly` / `codes.Unimplemented` responses for features
above the licensed tier.

### Professional+ Features

| Feature | Description |
|---------|-------------|
| **SIEM Integration** | Forward audit events to Splunk, Elasticsearch, QRadar, Sentinel, SumoLogic, LogRhythm, ArcSight, Syslog, Datadog, CloudWatch, SecurityHub (11 platforms) |
| **ML Threat Detection** | Char CNN-BiLSTM neural network (1.58M params, ONNX) for adversarial pattern detection with 100/100 evasion resistance |
| **Trust Framework** | Cryptographic agent identity, per-session trust scoring, pillar-based governance, and signed attestations |
| **Federated IOC** | Cross-organization indicator-of-compromise sharing |
| **Incident Response** | Automated playbook-driven incident management (14 default playbooks) |
| **CISO Posture Digest** | Signed posture digest with IOC, audit, and posture sources |
| **Trust Portal** | Public-facing trust page with posture, frameworks, and uptime snapshots |

### Enterprise Features

| Feature | Description |
|---------|-------------|
| **HSM Support** | Hardware Security Module integration for key management |
| **FIPS 140** | FIPS 140-2/140-3 cryptographic compliance mode |
| **Air-Gapped Deployment** | Fully offline deployment for regulated environments |
| **Kubernetes Clustering** | Multi-node clustering with Helm charts |
| **VM Sandboxing** | VM-level sandboxing for MCP agent isolation |
| **Custom ML Models** | Customer-supplied ML models for threat detection |

## Quick Start

```bash
# Build
go build -o aegisgate ./cmd/aegisgate-platform

# Run with defaults (in-memory stores)
./aegisgate

# Run with PostgreSQL
export DATABASE_URL="postgres://user:pass@localhost:5432/aegisgate"
./aegisgate

# Integration tests (requires Docker for PostgreSQL testcontainers)
go test -tags=integration -timeout 300s ./tests/integration/...
```

## Architecture

```
cmd/aegisgate-platform/     # Binary entry point
pkg/
├── a2a/                    # Agent-to-Agent security
├── acp/                    # Agent Capability Policy
├── analytics/              # Token usage and request metrics
├── attestation/            # Cryptographic attestation (RFC 3161 TSA)
├── audit/                  # Audit logging + SIEM dispatcher (enterprise: full SIEM)
├── audit/soc2/             # SOC 2 evidence collection
├── bridge/                 # Platform bridge for Lens integration
├── compliance/             # 31 framework modules across 33 subdirectories
├── cluster/                # HA clustering & distributed rate limiting
├── correlation/            # Event correlation engine
├── cve/                    # CVE-for-AI feed
├── digest/                 # CISO posture digest
├── evidence/               # Evidence collection and packaging
├── grpc/                   # gRPC service layer (7 services, 50 RPCs)
├── incident/               # Incident response (PostgreSQL + in-memory, 14 playbooks)
├── ioc/                    # IOC management and STIX export
├── lensbackend/            # Lens extension backend
├── mcpserver/              # MCP guardrails
├── metrics/                # Prometheus metrics
├── ml/                     # ML threat detection (enterprise: ONNX inference)
├── persistence/            # Storage backends (file + PostgreSQL)
├── platformconfig/         # Configuration with hot-reload
├── posture/                # Security posture assessment
├── promptcache/            # Prompt caching
├── rbac/                   # Role-based access control
├── response/               # 6-pillar response guard
├── response/detectors/     # 153-pattern detection engine
├── scanner/                # Vulnerability scanner
├── security/               # Security utilities
├── signature_verification/ # Package signature verification
├── sla/                    # SLA tracking
├── soc/                    # SOC detection patterns
├── sso/                    # SSO/OIDC
├── tier/                   # Tier definitions and feature gating
├── tieradapter/            # Tier adapter for runtime tier checks
├── toolauth/               # MCP tool authorization matrix
├── trustportal/            # Trust portal HTTP handlers (enterprise: full portal)
└── upstream/               # Vendored upstream packages (proxy, dashboard, opsec)
```

## Testing

```bash
# Unit tests (83.1% coverage, 8000+ tests across 441 files)
go test ./...

# Integration tests (requires Docker for PostgreSQL testcontainers)
go test -tags=integration -timeout 300s ./tests/integration/...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total
```

## License

Apache 2.0 for the community edition — see [LICENSE](LICENSE). Enterprise features are proprietary and require a license key.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

<div align="center">

[🌐 AegisGate Security](https://aegisgatesecurity.io) · [✉️ support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io) · [🐦 X/Twitter](https://x.com/aegisgate) · [🐘 Mastodon](https://mastodon.social/@aegisgate)

Made with 🖤 by AegisGate Security developers to secure the AI attack surface.

</div>