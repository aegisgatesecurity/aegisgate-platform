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

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability:

1. **DO NOT** open a public issue
2. Email **security@aegisgatesecurity.io** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Your contact information (optional)

We will respond within **48 hours** and work to resolve the issue within **90 days**.

## Security Measures

### Code Security

- ✅ All code reviewed before merge
- ✅ Security checks run on every PR
- ✅ No secrets in codebase (verified by TruffleHog)
- ✅ Dependencies scanned weekly
- ✅ Security advisories monitored

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
