# AegisGate Platform v1.3.5 — Release Notes

**Release Date:** 2026-04-24
**Tag:** `v1.3.5`
**Go Version:** 1.25.9

---

## 🎯 Release Summary

**Sprint 3 — Compliance Registry Wiring** is now complete. This release delivers:
- 8+ compliance frameworks running tier-aware checks
- MITRE ATLAS and NIST AI RMF mandated for all tiers (including Community)
- Premium frameworks (HIPAA, PCI-DSS, SOC2, GDPR, ISO 27001, ISO 42001) tier-gated
- MCP compliance adapter for session-scoped compliance enforcement

---

## 📦 What's New

### Compliance Framework Wiring (Sprint 3)

| Framework | Tier Access | Status |
|-----------|-------------|--------|
| MITRE ATLAS | Community+ | ✅ Mandatory |
| NIST AI RMF 1.0 | Community+ | ✅ Mandatory |
| OWASP LLM Top 10 | Developer+ | ✅ Wired |
| ISO 27001 | Developer+ | ✅ Wired |
| GDPR Basic | Developer+ | ✅ Wired |
| GDPR Advanced | Professional+ | ✅ Wired |
| HIPAA | Professional+ | ✅ Wired |
| PCI-DSS | Professional+ | ✅ Wired |
| SOC2 Type I | Professional+ | ✅ Wired |
| ISO 42001 | Enterprise | ✅ Wired |

### Security Enhancements (Sprint 3b — Complete)

| Feature | Description | Status |
|---------|-------------|--------|
| STDIO Validation | Shell metacharacter injection prevention | ✅ Complete |
| MCP Registration Gating | Client IP and server ID logging | ✅ Complete |
| Signature Verification | MCP registration signature verification | ✅ Complete |
| Authentication | Enabled by default (opt-out via `REQUIRE_AUTH=false`) | ✅ Complete |
| Memory Limits | Hard-enforced for Community tier | ✅ Complete |
| Tool Call Limits | 20 tools/session max for Community tier | ✅ Complete |
| Tool Authorization | Risk matrix (low/medium/high/critical) | ✅ Complete |

---

## 🔧 Technical Changes

### New Files
- `pkg/compliance/mcp_compliance.go` — Tier-aware compliance adapter (267 LOC)
- `pkg/compliance/mcp_compliance_test.go` — 14 compliance integration tests
- `pkg/signature_verification/mcp_verifier.go` — MCP signature verification adapter
- `pkg/signature_verification/mcp_verifier_test.go` — 20 signature verification tests

### Package Coverage
| Package | Coverage |
|---------|----------|
| tier | 100.0% |
| platformconfig | 98.6% |
| toolauth | 96.2% |
| rbac | 93.9% |
| metrics | 93.1% |
| auth | 90.3% |
| persistence | 89.7% |
| mcpserver | 87.2% |
| certinit | 87.2% |
| license | 86.9% |
| signature_verification | 67.4% |
| **Overall** | **~85%** |

---

## ⚠️ Breaking Changes

| Change | Impact | Mitigation |
|--------|--------|------------|
| `RequireAuth: true` | Authentication enabled by default | Set `REQUIRE_AUTH=false` to opt out |
| Community tier frameworks | ATLAS/NIST mandatory | No action needed — this is a feature |
| Memory limits enforced | Community sessions limited to 1GB | Upgrade tier for higher limits |

---

## 🔄 Upgrade Guide

### From v1.3.3/v1.3.4 → v1.3.5

```bash
# Pull latest
git pull origin main

# Rebuild
go build -o aegisgate-platform ./cmd/aegisgate-platform

# Run tests
go test ./pkg/... -cover
```

### Configuration Changes

```yaml
# No configuration changes required
# Compliance frameworks are auto-enabled based on tier
```

---

## 📋 Supported Versions

| Version | Status | Support Until |
|---------|--------|---------------|
| **1.3.5** | ✅ **Current** | Active development |
| 1.3.4 | ❌ Deprecated | Upgrade to 1.3.5 |
| 1.3.3 | ❌ Deprecated | Upgrade to 1.3.5 |
| < 1.3.3 | ❌ Deprecated | Upgrade to 1.3.5 |

---

## 🐛 Bug Fixes

- S3b-03: Signature verification adapter now properly imports `crypto/x509`
- Fixed nil pointer in compliance findings filtering
- Session tier information properly initialized in `NewMCPSessionCompliance`

---

## 🔒 Security

- **STDIO Command Validation:** Blocks shell metacharacters (`|`, `;`, `$()`, `` ` ``, `>`, `&`)
- **MCP Registration Gating:** Logs client IP, server ID, timestamp for audit
- **Signature Verification:** RSA/ECDSA/Ed25519 support for MCP handshakes
- **Memory Limits:** Community tier limited to 1GB per session (DoS protection)
- **Tool Call Limits:** Community tier limited to 20 tool calls per session

---

## 📚 Documentation

- [CHANGELOG.md](CHANGELOG.md) — Detailed change history
- [PERFORMANCE.md](PERFORMANCE.md) — Benchmarks and coverage metrics
- [SECURITY.md](SECURITY.md) — Security policy and reporting
- [plans/01-sprint-backlog.md](plans/01-sprint-backlog.md) — Sprint progress

---

## 🤝 Contributing

See [DCO.md](DCO.md) for commit sign-off requirements.
See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community guidelines.

---

**Signed-off-by:** AegisGate Security `security@aegisgatesecurity.io`