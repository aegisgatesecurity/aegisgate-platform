# AegisGate Platform v3.4.0 Release Notes

**Release Date**: 2026-07-23
**Status**: General Availability (GA)

## Overview

AegisGate Platform v3.4.0 is the general-availability release. It delivers full detection parity with AegisGate Lens (153 patterns), PostgreSQL persistence with integration tests, FedRAMP compliance (150 controls), 5 new compliance modules, multi-tenant isolation, and 4 production bug fixes.

## Breaking Changes

None. All changes are backward-compatible. The new `tenant_id` column (migration 004) defaults to `''` for existing rows.

## New Features

### Detection Engine — 153 Patterns (Full Lens Parity)

A new `pkg/response/detectors/` package ports all 153 regex detection patterns from AegisGate Lens:

- **45 secret patterns**: AWS, GitHub, GCP, Azure, JWT, Stripe, OpenAI, Anthropic, GitLab, npm, PyPI, Supabase, DigitalOcean, Linode, Vercel, Groq, Replicate, Cursor, and more
- **12 XSS patterns**: script tags, event handlers, javascript/data URLs, SVG abuse, mXSS, polyglot, DOM clobbering
- **15 PII US Core patterns**: SSN, email, phone, credit card, DOB, address, driver license, passport, EIN, bank account, IP, MRN, ICD-10, NPI
- **13 PII US Extended patterns**: loose credit card, CJK email, international phone, generic IDs, French SSN, Russian SNILS, Swiss UID, IPv6
- **9 PII Financial patterns**: BTC, ETH, BNB, LTC, SOL, PayPal, Stripe, Venmo, Cash App
- **24 PII International patterns**: Brazilian CPF, Indian Aadhaar, UK NHS, Australian TFN, Canadian SIN, IBAN, BIP39 seed, passports, national IDs
- **35 Compliance patterns**: OWASP LLM Top 10, MITRE ATLAS, EU AI Act, GDPR, CCPA, LGPD, PIPEDA, POPIA, NIST CSF, ISO 27001, toxicity detection

The ResponseGuard pipeline now runs 7 detection stages: PII → Secrets → XSS → Compliance → Token Limit → Toxicity → Hallucination.

### PostgreSQL Integration Tests

6 packages have testcontainers-go integration test suites (107 total tests):

- `pkg/ioc/` (17 tests) — including migration bug fixes
- `pkg/persistence/` (17 tests)
- `pkg/rbac/` (27 tests)
- `pkg/license/` (12 tests)
- `pkg/correlation/` (20 tests)
- `pkg/attestation/` (14 tests)

### FedRAMP — 150 NIST 800-53 Controls

`pkg/compliance/fedramp/` covers 150 controls across 18 families (Moderate baseline). Includes cross-framework traceability via hub-and-spoke model.

### 5 New Compliance Modules

| Module | Controls | Coverage |
|--------|----------|----------|
| CMMC Level 2 | 14 domains | 98.3% |
| NIST 800-171 | 14 families | 99.6% |
| HITRUST CSF | 6 categories | 100% |
| TISAX | 7 categories | 100% |
| ISO 27001 | 14 categories | 98.9% |

### Multi-Tenant Isolation

Migration 004 adds `tenant_id` to 6 tables with tenant-scoped indexes. Four `TenantContext` structs provide consistent isolation across IOC, RBAC, license, and persistence packages.

### Incident Response Engine

`pkg/incident/` provides automated detection rules, playbooks, and compliance mapping.

### SOC 2 Audit Automation

`pkg/audit/soc2/` provides evidence collection, policy templates, and workpapers.

### SSE Real-Time Streaming

`pkg/soc/` adds Server-Sent Events for the SOC incident timeline.

## Bug Fixes

1. **Migration 002 tsvector bug**: `to_tsvector('english', message) || to_tsvector('english', COALESCE(data::text, ''))` fails in `CREATE INDEX`. Fixed with `audit_tsvector_search()` IMMUTABLE function wrapper.
2. **RBAC `GetAgentSessions`**: SELECT missing `tenant_id` column (9 vs 10 expected). Fixed.
3. **Attestation `Store` zero `ValidUntil`**: Stored `0001-01-01` instead of NULL, causing `PruneExpired` to delete non-expiring envelopes. Fixed with nil interface{} for zero time.
4. **IOC `migrate()` chicken-and-egg**: Queries `ioc_schema_migrations` before creating it. Fixed with `CREATE TABLE IF NOT EXISTS` preamble.

## Security

- **GO-2026-5932** (`golang.org/x/crypto/openpgp`): Documented suppression in `govulncheck.toml`. Our code does not call openpgp (confirmed by `govulncheck` exit 0).

## Dependencies

- **Added**: `testcontainers-go`, `testcontainers-go/modules/postgres` (integration tests only)
- **No new runtime dependencies** since v3.3.0-beta.2

## Compatibility

- Go 1.26.5+
- PostgreSQL 16+ (for persistence backend)
- Docker (for integration tests)

## Full Changelog

https://github.com/aegisgatesecurity/aegisgate-platform/compare/v3.3.0-beta.2...v3.4.0