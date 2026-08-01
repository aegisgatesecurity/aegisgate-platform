# AegisGate Platform v3.6.0 Release Notes

**Release Date**: 2026-08-01
**Status**: General Availability (GA)

## Overview

AegisGate Platform v3.6.0 is a hard version rebaseline release focused on security hardening, detection accuracy, and ML pipeline foundation. ATLAS false-positive rate eliminated (30.8%→0.0%), evasion-resistant normalization, rule integrity verification, 70% proxy overhead reduction, and the Char CNN-BiLSTM data pipeline for v4 ML-based threat detection. 15 commits, 55 packages passing, 0 race conditions.

## Breaking Changes

None. v3.6.0 is fully backward-compatible with v3.5.0.

## Security Fixes

- **P0/P1 bug fixes** across scanner, proxy, and compliance engine — content extraction, token smuggling regex, ATLAS over-matching
- **ATLAS FPR 30.8%→0.0%** — 16 context-aware pattern refinements; zero false positives on the ATLAS benchmark suite while maintaining 78.8% TPR
- **Unicode homoglyph language detection** — catches confusable-script attacks (Cyrillic, Greek, Armenian) while preserving multilingual input

## Performance

- **70% proxy overhead reduction** — request processing pipeline re-architected for throughput
- 24,806 peak RPS sustained on benchmark hardware

## Detection & Evasion Resistance

- **Evasion-resistant normalization pipeline** — sliding ROT13, aggressive repeating-char collapse, Unicode canonicalization (+4.7 pts evasion score)
- **Multi-turn attack detection** — conversation-level attack pattern recognition across request sequences
- **Aggressive repeating-char detection** — catches `iiiiii` and `!!!!` style evasion padding (+1.8 pts)
- **Sliding ROT13 detection** — catches `Ebg13` and `Ceboyrz` style obfuscation

## ML Pipeline (v4 Foundation)

- **Char CNN-BiLSTM data pipeline** — detector, calibrator, and normalizer for ML-based threat detection
- **Benign corpus: 10,000+ examples** across 15 categories for training and calibration
- **ML feature flags** — `AEGIS_ML_THREAT_DETECTION_ENABLED` and `AEGIS_ML_SHADOW_MODE` for cold-start deployment
- **Graceful degradation** — rules-only mode with 0% FPR guarantee; shadow mode for safe ML validation

## Compliance

- **ATLAS playbooks: 10 new playbooks** (66→76 technique coverage with context)
- **Rule integrity verification** — SHA256 hash endpoint at `GET /api/v1/compliance/integrity` for audit verification of all loaded pattern sets
- **MTTI auto-enrichment** — 52 ATLAS sub-techniques auto-mapped to detection rules with severity and recommended response

## Testing

- 55 packages passing, 0 failures, 0 race conditions
- Benign corpus FPR: 0.0% (200/200)
- ATLAS pattern FPR: 0.0% (0/52 adversarial patterns produce false positives on benign input)
- Docker image: 34.7MB, Alpine-based, non-root, FIPS-ready

---

# AegisGate Platform v3.5.0 Release Notes

**Release Date**: 2026-07-28
**Status**: General Availability (GA)

## Overview

AegisGate Platform v3.5.0 is a major feature release focused on compliance engine maturation and production infrastructure. It delivers FedRAMP automation from 82 to 151 controls (88.8%), gRPC service layer, Trust API attestation, SIEM promotion, SSO PostgreSQL persistence, token analytics, and PDF export. 17 commits, 93 packages, 0 race conditions.

## Breaking Changes

- **Starter tier removed from billing.** Community is free, Developer ($79/mo) is the first paid tier. The `inferTierFromAmount()` function now maps amounts under $79 to "developer" (Community is not a paid tier). Any Stripe metadata referencing `tier=starter` will be rejected by `tier.ParseTier()`.

## New Features

### Compliance Engine v2 — FedRAMP 151/170 Automated (88.8%)

Two waves of CheckFunc promotion bring FedRAMP from 82/170 (48%) to 151/170 (88.8%):

- **T8 (38 controls)**: Bulk promotion from manual/evidence-mapped to automated CheckFuncs. Scanner-backed checks for AC, AU, CM, IA, RA, SC, SI families.
- **P3 (31 controls)**: Second wave promoting evidence-mapped controls that had stubs but no real verification logic. Now checks platform config for real capabilities (scanner integration, RBAC policies, SIEM forwarding, etc.).
- **Bug fix**: 5 controls (SA-9(1), SA-11(1), SC-15(1), SI-4(1), SR-8(1)) had duplicate registrations where Go map last-write-wins silently overrode automated CheckFuncs with manual stubs. Fixed by removing the duplicate stubs.
- **19 remaining controls** are genuinely customer-responsibility: policy-only (AC-1, AU-1, CM-1, IA-1, IR-1, PL-1, RA-1, SC-1), HR/personnel (PS-1, PS-2, PS-3, PM-1, PM-14), physical security (PE-3, PE-20), and process documents (CA-1, MA-1, PL-2, SA-9). These cannot be verified by any vendor's software.

### gRPC Service Layer

7 gRPC services with 50 RPCs, health checking, server reflection, and TLS support:

- `ComplianceService`: Framework listing, control checking, evidence retrieval
- `ScannerService`: Pattern detection, scan requests, result streaming
- `TrustService`: Attestation generation/verification, score queries
- `SSOService`: Session management, provider configuration
- `AuditService`: Event retrieval, export, TSA timestamping
- `AnalyticsService`: Token usage metrics, dashboard data
- `HealthService`: gRPC health checking per gRPC spec

### Trust API Attestation

- `AttestationGenerator` and `AttestationValidator` now wired into Trust API endpoints
- Real attestation generation with cryptographic signing (no more stub responses)
- TSA (RFC 3161) timestamping wired into audit pipeline for non-repudiation

### SIEM Promotion

- `pkg/siem/` promoted from stub to production package
- Public API with config bridging from `platformconfig`
- Health check endpoint
- Forwarder registration for Splunk, Datadog, ELK

### SSO PostgreSQL Persistence

- OIDC sessions persist to PostgreSQL with TTL handling and session cleanup
- ACR value mapping: IdP assurance levels map to AegisGate assurance levels
- Session state survives platform restarts

### Token Analytics

- `RecordUsage()` wired into every API request path
- Per-request metrics: model, tokens, latency, tier
- Analytics dashboard has real data

### PDF Export

- Questionnaire results export to properly formatted PDF
- Compliance scoring, evidence citations, executive summary
- Replaces the previous `return nil` stub

## Bug Fixes

1. **Trust API attestation wiring**: `AttestationGenerator` and `AttestationValidator` were not wired into Trust API handlers. Fixed.
2. **SSO ACR values**: SSO was accepting all ACR values without verification. Now maps IdP ACR values to platform assurance levels. Fixed.
3. **FedRAMP duplicate registrations**: 5 controls had duplicate registrations where manual stubs overrode automated CheckFuncs via Go map last-write-wins. Fixed by removing duplicate stubs.

## Testing

- 93 packages, 0 failures, 0 race conditions
- 5 consecutive full test suite runs confirmed stable
- Stripe webhook integration validated (HMAC-SHA256, ToS audit, module parsing, tier validation)

## Compatibility

- Go 1.26.5+
- PostgreSQL 16+ (for persistence, SSO, RBAC)
- Docker (for production deployment)

## Full Changelog

https://github.com/aegisgatesecurity/aegisgate-platform/compare/v3.4.3...v3.5.0