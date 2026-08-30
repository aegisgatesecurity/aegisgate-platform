# AegisGate Platform Release Notes

**Current Release**: v4.3.3 (2026-08-29)
**Status**: General Availability (GA)

For full release history, see [CHANGELOG.md](CHANGELOG.md).

## v4.3.3 — SSRF Remediation (HIGH-2)

Remediates the final HIGH finding from the adversarial security audit: SSRF via MCP `http_request` tool. Multi-layer SSRF defense with URL validation and custom HTTP transport dialer for DNS rebinding prevention. 60+ test cases covering all attack vectors.

All 13 adversarial audit findings (1 CRITICAL, 3 HIGH, 5 MEDIUM, 4 LOW) are now resolved.

## v4.3.2 — Security Audit Remediation

Resolves all 28 findings from the comprehensive 5-phase security audit. SAML signature validation, A2A replay protection, RLS enforcement for all stores, path traversal fix, health info disclosure, IOC rate limiting, JWT key validation, and more.

## v4.0.0 — ML Threat Detection + Six-Pillar Architecture

Major release: ML threat detection (ONNX inference), six-pillar architecture (HTTP API, MCP, A2A, ACP, RESPONSE, Trust Framework), 31 compliance frameworks, 12 SIEM + 4 SOAR integrations, web UI, air-gapped deployment.

## Archived Versions

All versions prior to v4.3.3 are End-of-Life (EOL) and no longer receive security fixes.
See [SECURITY.md](SECURITY.md) for the supported versions policy.
