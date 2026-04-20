<div align="center">

# 🛡️ AegisGate Platform™ — Enterprise AI Security Gateway

[![Version](https://img.shields.io/github/v/release/aegisgatesecurity/aegisgate-platform?label=version&logo=semver)](https://github.com/aegisgatesecurity/aegisgate-platform/releases)
[![License](https://img.shields.io/github/license/aegisgatesecurity/aegisgate-platform?color=blue)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25.9+-00ADD8?logo=go)](https://golang.org/)
[![Security](https://img.shields.io/badge/Security-0_CVEs-brightgreen?logo=shield)](SECURITY.md)
[![Test Coverage](https://img.shields.io/badge/Coverage-79.9%25-green?logo=codecov)](https://github.com/aegisgatesecurity/aegisgate-platform/actions)

[![Docker](https://img.shields.io/badge/Docker-19.1MB-2496ED?logo=docker)](Dockerfile)
[![Kubernetes](https://img.shields.io/badge/K8s-Ready-326CE5?logo=kubernetes)](deploy/helm/aegisgate-platform/)
[![Performance](https://img.shields.io/badge/Performance-11K_RPS-orange?logo=lightning)](PERFORMANCE.md)
[![Community](https://img.shields.io/badge/Mastodon-@aegisgatesecurity-6364FF?logo=mastodon)](https://mastodon.social/@aegisgatesecurity)

[📚 Docs](https://github.com/aegisgatesecurity/aegisgate-platform/tree/main/docs) &nbsp;•&nbsp; [✨ Features](#features) &nbsp;•&nbsp; [🚀 Quick Start](#-quick-start) &nbsp;•&nbsp; [🏗️ Architecture](#-architecture) &nbsp;•&nbsp; [⚡ Performance](PERFORMANCE.md) &nbsp;•&nbsp; [🔒 Security](SECURITY.md)

</div>

> **30-Second Pitch**: Your AI applications need enterprise-grade security — but shouldn't require enterprise budgets. AegisGate Platform™ provides unified AI traffic inspection, MCP security guardrails, and compliance automation in a single 19MB binary. Deploy in 60 seconds. Sleep better tonight.

---

## ⚡ TL;DR

**AegisGate Platform™** is a unified AI security gateway that consolidates HTTP proxy security, MCP protocol protection, and administrative dashboard into a single high-performance binary.

| 🛡️ **Security** | 📋 **Compliance** | 🚀 **Performance** |
|-----------------|------------------|-------------------|
| Real-time threat scanning | **MITRE ATLAS** (free) | **2.44ms avg latency** |
| Prompt injection prevention | **NIST AI RMF** (free) | **11,681 RPS peak** |
| MCP tool authorization | SOC2, GDPR, HIPAA | **19.1MB Docker image** |
| Data leakage protection | OWASP LLM Top 10 | **0 CVEs** |
| RBAC & audit logging | ISO 27001/42001 | **2,350+ tests passing** |

**Zero Configuration Required.** Download, run, secure. No external dependencies. No paid services. Ever.

---

## 🎯 What Makes AegisGate Platform Different?

### Traditional Approach
```
Your App → Proxy (security) → MCP Server (tools) → Audit System (compliance)
         ↓                    ↓                      ↓
       3 separate          3 separate            3 separate
       deployments         configs               dashboards
```

### AegisGate Platform Approach
```
Your App → [ HTTP Proxy | MCP Server | Dashboard ] → Secure AI
              ↓                ↓              ↓
           One binary    One config    One view
```

**Unified. Simplified. Enterprise-grade.**

---

## 🔒 Security

Our code security matches our product security:

- **8 security tools** run on every commit
- **0 known CVEs** in production dependencies
- **SARIF reporting** to GitHub Security tab
- **SBOM generation** (CycloneDX + SPDX)
- **Secret scanning** with TruffleHog
- **Vulnerability scanning** with govulncheck + Trivy

See [SECURITY.md](SECURITY.md) for details.

---

## 📦 License & Contribution Model

### Apache License 2.0 — Community Edition

AegisGate Platform™ Community Edition is released under the [Apache License 2.0](LICENSE). This covers the open-source codebase published in this repository.

- ✅ Use the software for any purpose
- ✅ Modify and distribute the software
- ✅ Use in proprietary software
- ✅ Distribute copies to others

**Commercial features** — including enterprise compliance frameworks, advanced threat detection, and priority support — are available under a separate commercial license. See [NOTICE](NOTICE) for trademark and licensing details, or contact [sales@aegisgatesecurity.io](mailto:sales@aegisgatesecurity.io).

### Contribution Model

Contributions are welcome under the [inbound=outbound](https://opensource.microsoft.com/outbound/) model. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Every commit requires a `Signed-off-by` per our [DCO](DCO.md). No CLA required.

---

## ✨ Features

### Unified Security Gateway

| Component | Port | Purpose |
|-----------|------|---------|
| **HTTP Proxy** | `:8080` | AI API traffic inspection, PII scanning, rate limiting |
| **MCP Server** | `:8081` | Model Context Protocol security, tool authorization |
| **Dashboard** | `:8443` | Real-time monitoring, compliance status, audit logs |

### Security Protection

| Feature | Description | Status |
|---------|-------------|--------|
| **Prompt Injection Prevention** | Blocks OWASP LLM Top 10 attacks | ✅ |
| **Data Leakage Protection** | PII, secrets, credentials detection | ✅ |
| **Adversarial Attack Defense** | Jailbreaks, DoS, manipulation detection | ✅ |
| **MCP Tool Guardrails** | Per-tool authorization policies | ✅ |
| **RBAC Access Control** | Role-based permissions | ✅ |
| **Audit Logging** | RFC5424-compliant, tamper-evident | ✅ |
| **Circuit Breaker** | Automatic failure recovery | ✅ |
| **Auto-Certificate Generation** | Built-in CA, zero-config TLS | ✅ |

### Compliance Frameworks (Community Tier)

| Framework | Coverage | Availability |
|-----------|----------|--------------|
| **MITRE ATLAS** | All AI-specific attack patterns | ✅ |
| **NIST AI RMF** | Complete AI risk management | ✅ |
| **OWASP LLM Top 10** | LLM01-LLM10 coverage | ✅ |
| **SOC 2** | Security controls | ✅ |
| **HIPAA** | Healthcare data protection | ✅ |
| **GDPR** | EU data protection | ✅ |
| **ISO 27001** | Information security | ✅ |
| **ISO 42001** | AI management systems | ✅ |
| **PCI-DSS** | Payment card security | ✅ |

---

## 🚀 Quick Start

### Docker (Recommended)

```bash
docker run -d \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 8443:8443 \
  -v $(pwd)/data:/data \
  ghcr.io/aegisgatesecurity/aegisgate-platform/aegisgate:latest \
  --embedded-mcp --tier=community
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/aegisgatesecurity/aegisgate-platform.git
cd aegisgate-platform

# Build and run
go build -o aegisgate-platform ./cmd/aegisgate-platform
./aegisgate-platform --embedded-mcp --tier=community
```

### Verify Installation

```bash
# Health check
curl http://localhost:8443/health

# Dashboard (self-signed cert OK)
open https://localhost:8443

# MCP server test
nc -zv localhost 8081
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AEGISGATE PLATFORM                        │
│                     (Single Binary)                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  HTTP Proxy  │  │ MCP Server   │  │  Dashboard   │    │
│  │  :8080       │  │  :8081       │  │  :8443       │    │
│  │              │  │              │  │              │    │
│  │ • Scanning   │  │ • Guardrails │  │ • Health     │    │
│  │ • PII detect │  │ • RBAC       │  │ • Metrics    │    │
│  │ • Rate limit │  │ • Audit      │  │ • Compliance │    │
│  │ • Circuit    │  │ • Tools      │  │ • Logs       │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                  │                  │           │
│         └──────────────────┼──────────────────┘           │
│                            │                              │
│                   ┌────────┴────────┐                      │
│                   │  Tier Adapter   │                      │
│                   │  (91 Features)  │                      │
│                   └────────┬────────┘                      │
│                            │                              │
│         ┌──────────────────┼──────────────────┐           │
│         │                  │                  │           │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐   │
│  │ Persistence  │  │   CertInit   │  │   Scanner    │   │
│  │ /data/audit  │  │  Auto-CA     │  │   PII/Secret │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Performance

**Load tested with k6. See [PERFORMANCE.md](PERFORMANCE.md) for full details.**

| Metric | Result | Grade |
|--------|--------|-------|
| **Peak Throughput** | 11,681 RPS | ✅ Outstanding |
| **Average Latency** | 2.44ms | ✅ Excellent |
| **P95 Latency** | 3.64ms | ✅ Excellent |
| **P99 Latency** | 8.17ms | ✅ Excellent |
| **Error Rate** | 0.00% | ✅ Perfect |
| **Binary Size** | 14.3MB | ✅ Optimized |
| **Docker Image** | 19.1MB | ✅ Minimal |
| **Test Coverage** | 85%+ | ✅ Comprehensive |

**Total Tests: 2,350+ (2,348 PASS, 1 SKIP)**

---

## 🛠️ Configuration

### Zero-Config (Just Run)

```bash
aegisgate-platform --embedded-mcp --tier=community
```

### With Custom Config

```yaml
# aegisgate-platform.yaml
proxy:
  bind_address: :8080
  upstream_url: https://api.openai.com
  
server:
  port: 8443
  dashboard_port: 8443
  
mcp:
  enabled: true
  port: 8081
  
persistence:
  data_dir: /data
  audit_dir: /data/audit
  enabled: true
  
tier: community
log_level: info
```

### Environment Variables

```bash
export AEGISGATE_PROXY_BIND_ADDRESS=:8080
export AEGISGATE_DASHBOARD_PORT=8443
export AEGISGATE_TIER=community
export AEGISGATE_LOG_LEVEL=info
```

---

## 🔄 Integration Examples

### OpenAI Client

```python
import openai

# Point to AegisGate instead of OpenAI directly
openai.api_base = "http://localhost:8080"

response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello, world!"}]
)
```

### MCP Client

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';

const client = new Client(
  { name: 'my-app', version: '1.0.0' },
  { capabilities: {} }
);

// Connect through AegisGate security layer
await client.connect({
  command: 'node',
  args: ['-e', 'require("net").connect(8081)'],
});
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | This file — overview and quick start |
| [PERFORMANCE.md](PERFORMANCE.md) | Load testing results and benchmarks |
| [SECURITY.md](SECURITY.md) | Security policies and vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [DCO.md](DCO.md) | Developer Certificate of Origin |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [LICENSE](LICENSE) | Apache 2.0 license text |
| [NOTICE](NOTICE) | Trademark reservation and commercial licensing |
| [TRADEMARKS.md](TRADEMARKS.md) | Trademark usage policy |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

---

## 🤝 Community

- **Mastodon**: [@aegisgatesecurity](https://mastodon.social/@aegisgatesecurity)
- **GitHub Discussions**: [github.com/aegisgatesecurity/aegisgate-platform/discussions](https://github.com/aegisgatesecurity/aegisgate-platform/discussions)
- **Issues**: [github.com/aegisgatesecurity/aegisgate-platform/issues](https://github.com/aegisgatesecurity/aegisgate-platform/issues)

---

## 📧 Contact

| Purpose | Email |
|---------|-------|
| Sales | sales@aegisgatesecurity.io |
| Security | security@aegisgatesecurity.io |
| Support | support@aegisgatesecurity.io |

---

## 🙏 Acknowledgments

- [MCP Protocol](https://modelcontextprotocol.io) — Model Context Protocol
- [MITRE ATLAS](https://atlas.mitre.org) — AI threat framework
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) — AI risk management
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — LLM security

---

<div align="center">

**[aegisgatesecurity.io](https://aegisgatesecurity.io)**

Built with 🖤 by the AegisGate Security team

© 2024-2026 AegisGate Security, LLC

</div>
