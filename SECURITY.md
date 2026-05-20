# Security Policy

## Supported Versions

| Version | Supported | Security Fixes |
|---------|-----------|----------------|
| v1.3.x  | ✅ Yes    | Active support |
| v1.2.x  | ⚠️ Limited | Critical only |
| < v1.2  | ❌ No      | Please upgrade |

## Security Features

AegisGate Platform implements comprehensive security scanning:

| Tool | Purpose | Frequency |
|------|---------|-----------|
| **govulncheck** | Go vulnerability database | Every push |
| **gosec** | Static security analysis | Every push |
| **Trivy** | Container & filesystem scan | Every push + weekly |
| **TruffleHog** | Secret detection | Every push |
| **go vet** | Standard Go analysis | Every push |
| **staticcheck** | Advanced static analysis | Every push |

## Security Certifications

| Status | Item |
|--------|------|
| ✅ | **0 Known CVEs** in production dependencies |
| ✅ | **Fuzz Testing** integrated for critical paths |
| ✅ | **SBOM Generation** (CycloneDX + SPDX) |
| ✅ | **Dependency Vulnerability Scanning** |
| ✅ | **Secret Scanning** (AWS keys, GitHub tokens, etc.) |
| ✅ | **Authentication-by-Default** (v1.3.6) |
| ✅ | **Hard-Enforced Memory Limits** (v1.3.6) |
| ✅ | **MCP Registration Logging** (v1.3.6) |
| ✅ | **Tool Call Limits** (v1.3.6) |
| ✅ | **Risk-Based Authorization** (v1.3.6) |
| ✅ | **90.8% Test Coverage** (v1.3.6) |

## Threat Model (v3.0)

Comprehensive threat analysis for all four security pillars:

| Document | Purpose | Key Content |
|----------|---------|-------------|
| [plans/THREAT-MODEL.md](plans/THREAT-MODEL.md) | Full threat model | STRIDE, DFD, attack trees, CVSS, ATLAS |
| [plans/a2a-threat-analysis.md](plans/a2a-threat-analysis.md) | A2A-specific | 10 ATLAS-A2A patterns |
| [plans/v3.0-ROADMAP.md](plans/v3.0-ROADMAP.md) | Implementation | v3.0 roadmap |

### Threat Categories Covered

| Pillar | Threats | Top Risk |
|--------|---------|----------|
| **HTTP API** | 10 STRIDE threats | License tier bypass (CVSS 9.8) |
| **MCP Protocol** | 10 STRIDE threats | Session spoofing (CVSS 9.5) |
| **A2A Agent** | 10 STRIDE threats | Agent impersonation (CVSS 9.1) |
| **AI Response** | 11 STRIDE threats | PII disclosure (CVSS 9.1) |

### CVSS Score Distribution

| Severity | Count | Range |
|----------|-------|-------|
| 🔴 Critical | 7 | 9.0–9.8 |
| 🟠 High | 11 | 7.0–8.9 |
| 🟡 Medium | 7 | 4.0–6.9 |

### MITRE ATLAS Coverage

| Category | Techniques | Status |
|----------|-----------|--------|
| ATLAS-MCP | 4 | ✅ All mitigated |
| ATLAS-A2A | 10 | ✅ All mitigated |
| ATLAS-LLM | 8 | ✅ All mitigated |
| ATLAS-RAG | 3 | 🔜 v4.0 planning |

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability:

1. **DO NOT** open a public issue
2. Email **security@aegisgatesecurity.io** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Your contact information (optional)

We will respond within **48 hours** and work to resolve the issue within **90 days**.

## Sprint 3b — MCP Security Enhancement Complete ✅

**v1.3.6 — released April 2026**

All critical OpenAI/X security concerns addressed:

| Feature | Status | Description |
|---------|--------|-------------|
| Authentication-by-Default | ✅ | All endpoints require auth unless `REQUIRE_AUTH=false` |
| MCP Registration Logging | ✅ | Client IP, server ID, timestamp logged for audit |
| Hard-Enforced Memory Limits | ✅ | Sessions terminated when exceeding quota |
| Tool Call Limits | ✅ | 20 tools/session enforced with proper error feedback |
| Risk-Based Authorization | ✅ | All tool calls checked against authorization matrix |
| Test Coverage | ✅ | 90.8% overall (93.9% RBAC, 96.2% ToolAuth, 88.3% MCP) |

### Code Security

### Runtime Security

- ✅ Non-root container execution
- ✅ Minimal attack surface (19.1MB image)
- ✅ Read-only filesystem support
- ✅ No external network dependencies
- ✅ TLS 1.3 by default

### Compliance

- ✅ **OWASP LLM Top 10** protection
- ✅ **MITRE ATLAS** threat detection
- ✅ **NIST AI RMF** compliance frameworks
- ✅ **GDPR** data protection controls

## Security Scanning Results

Our security workflow runs:

```yaml
# Jobs executed on every push
govulncheck:   # Go vulnerability scan
gosec:         # Security linter
trivy:         # Container scan
trufflehog:    # Secret detection
standard-tools: # go vet, staticcheck
sbom:          # SBOM generation
```

Results are available:
1. **GitHub Security Tab** - SARIF uploads
2. **Artifacts** - Download detailed reports
3. **GitHub Step Summary** - Quick overview

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities.

## Contact

- **Security Issues**: security@aegisgatesecurity.io
- **General Support**: support@aegisgatesecurity.io
