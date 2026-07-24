# Security Policy

## Supported Versions

| Version | Supported | Security Fixes |
|---------|-----------|----------------|
| v3.4.x  | ✅ Yes    | Active support |
| v3.3.x  | ✅ Yes    | Active support |
| v3.2.x  | ✅ Yes    | Active support |
| v3.1.x  | ⚠️ Limited | Critical only |
| v3.0.x  | ⚠️ Limited | Critical only |
| < v3.0  | ❌ No      | Please upgrade |

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
| ✅ | **0 Known CVEs** in production dependencies (transitive golang.org/x/* family addressed in PR #77; see [Code-Scanning Alerts](#code-scanning-alerts-updated-2026-07-01) below) |
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

## Threat Model (v3.4.0+)

Comprehensive threat analysis for all six security pillars:

### Threat Categories Covered

| Pillar | Threats | Top Risk |
|--------|---------|----------|
| **HTTP API** | 10 STRIDE threats | License tier bypass (CVSS 9.8) |
| **MCP Protocol** | 10 STRIDE threats | Session spoofing (CVSS 9.5) |
| **A2A Agent** | 10 STRIDE threats | Agent impersonation (CVSS 9.1) |
| **AI Response** | 11 STRIDE threats | PII disclosure (CVSS 9.1) |
| **ACP (Agent Communication Protocol)** | 12 STRIDE threats | HMAC bypass (CVSS 9.0) |
| **Trust Framework** | 10 STRIDE threats | Identity spoofing (CVSS 9.0) |

> **Total: 63 STRIDE threats documented** (see internal threat model for
> the full analysis with CVSS scoring and mitigation mappings). The Trust
> Framework was promoted to first-class 6th pillar in v3.2.0+ and expanded
> in v3.4.0+ with the envelope primitive.

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

## Code-Scanning Alerts (Updated 2026-07-01)

As of the latest code-scanning run, the Platform repo has open alerts
covering transitive dependencies in the golang.org/x family. These
were addressed in PR #77 (commits 833602f and 0594a35 on branch
fix/bug-c-parsedetections-remoteobject):

- 70 Trivy CVEs in golang.org/x/{net,crypto,sys} - bumped to fixed
  versions in root go.mod and upstream/aegisguard/go.mod
- 1 CodeQL G703 (path traversal) in tools/build-lens-extension/bundle.go -
  added isSafePathComponent() check before filepath.Join with
  directory-listed names

### Vendored legacy code (upstream/)

The Platform repo contains vendored copies of two pre-consolidation
products under upstream/:

- upstream/aegisgate/ - legacy AegisGate (pre-Platform)
- upstream/aegisguard/ - legacy AegisGuard (pre-Platform)

These directories are part of the Platform repo on the same remote
(github.com/aegisgatesecurity/aegisgate-platform) and are maintained
by the Platform team. CVE fixes apply to their go.mod files in the
same PR as the root go.mod.

### Pre-existing build break: upstream/aegisgate

upstream/aegisgate/go.mod declares module github.com/aegisgatesecurity/aegisgate
but its source code imports github.com/aegisgatesecurity/aegisgate-platform/pkg/license
and pkg/tier - packages that only exist in the Platform main module.
The build of this subtree was broken BEFORE the CVE work started
(verified by checking out the pre-CVE commit and observing the same
import errors). This is tracked separately as a refactor task
(establish the correct module path or add replace directives).

The dependency-version bumps in PR #77 still apply because the
upstream/aegisgate/go.mod versions are also updated, even though
the subtree does not build standalone. The next CI run on the
Platform main branch will surface the build error for triage.

### Verification

After the bumps in commit 0594a35:

- Root: go build ./... passes
- Root: go test ./tools/test-extension/ passes
- upstream/aegisguard: go build ./... passes
- upstream/aegisgate: pre-existing build break (see above)

The CodeQL workflow re-ran on commit 0594a35 and reported
results_count: 0. The Trivy scan re-ran and reported
results_count: 0 for the dependencies at the bumped versions.
GitHub code-scanning alert auto-resolution will mark the
individual alerts as fixed as the new scan results propagate.
