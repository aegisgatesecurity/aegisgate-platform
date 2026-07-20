## [Unreleased] - 2026-07-20 - v3.4.0+ Engineering-Complete (Awaiting v3.4.0 GA)

> **Not a version bump.** The work below is committed to `main` and engineering-complete. The v3.4.0 GA is gated on **legal review (H1) + the v3.4.0 paid pentest (H4)**, per the [Beta User Agreement](content/legal/beta-agreement.md) and the README. The version stays at v3.4.0-beta.1 (a forward-looking label for the in-progress work) until those gates are cleared. The public release remains **v3.3.0-beta.2**.

This is the engineering-complete summary of all work on `main` since v3.3.0-beta.2 (2026-06-08). It includes the v3.4.0+ Tier 5+3+4 sprint, the v0.2 wiring fixes, Phases 1–5 (PostgreSQL, Lens integration, SIEM wiring, IOC performance), and **Phase 6 (D11: Multi-Tenant Isolation)**.

### D11: Multi-Tenant Isolation Verification ✅ COMPLETE (2026-07-20)

**Last engineering blocker for Professional tier GA now resolved.**

#### Migration 004
- **File**: `pkg/ioc/migrations/004_multi_tenant.sql` (104 lines)
- Adds `tenant_id TEXT NOT NULL DEFAULT ''` to 6 tables: `ioc_fingerprints`, `ioc_events`, `rbac_agents`, `rbac_agent_sessions`, `rbac_user_sessions`, `license_cache`
- Changes `license_cache` primary key from `(license_key)` to `(tenant_id, license_key)` composite
- Creates 7 indexes for tenant-scoped queries
- Backward compatible: existing rows get `tenant_id = ''`

#### Tenant Context Pattern
Four context structs with consistent API across all packages:
```go
type TenantContext struct {
    TenantID string
    IsAdmin  bool // if true, can access cross-tenant data
}
```
- `ioc.TenantContext` — IOC store isolation
- `rbac.RBACTenantContext` — RBAC agent/session isolation
- `license.LicenseTenantContext` — license cache isolation
- `persistence.AuditTenantContext` — audit log isolation

#### Code Changes
| Package | Changes |
|---------|---------|
| `pkg/ioc/` | `TenantContext` struct, tenant filtering in `Query()`, `Snapshot()`, `Get()`, `Observe()`, `ObserveBatch()`, `SnapshotSince()`, `Size()` |
| `pkg/rbac/` | `RBACTenantContext` struct, tenant filtering in `RegisterAgent()`, `GetAgent()`, `ListAgents()`, `CreateAgentSession()`, `GetAgentSession()`, `GetUserSession()` |
| `pkg/license/` | `LicenseTenantContext` struct, tenant-scoped cache keys in `Get()`, `Set()`, `Invalidate()`, `PruneExpired()`, context helpers in `license.go` |
| `pkg/persistence/` | `AuditTenantContext` struct, `AuditFilter.TenantID` already provided isolation |

#### Design Decisions
- **Optional variadic parameters**: All tenant context parameters are `...TenantContext` (backward compatible)
- **Empty tenant_id**: Represents legacy/pre-multi-tenant data; accessible to all tenants
- **Admin override**: `IsAdmin=true` bypasses tenant filtering for cross-tenant dashboards/auditing
- **Zero breaking changes**: All existing code continues to work without modification

#### Testing
**23 comprehensive tenant isolation tests** created and passing:
- `pkg/ioc/tenant_isolation_test.go` (7 tests) — Tenant A cannot see Tenant B's IOCs, admin can see all, backward compatibility
- `pkg/rbac/tenant_isolation_test.go` (7 tests) — Agent/session isolation, tenant-scoped registration and lookups
- `pkg/license/tenant_isolation_test.go` (9 tests) — Tenant-scoped license cache, context propagation

All tests verify:
1. ✅ Tenant A cannot see Tenant B's data
2. ✅ Admin users CAN see cross-tenant data
3. ✅ Backward compatibility (empty tenant_id) works
4. ✅ IsAdmin flag controls access

#### Test Results
```
pkg/ioc       7 tests  ✅ PASS (0.009s)
pkg/rbac      7 tests  ✅ PASS (0.008s)
pkg/license   9 tests  ✅ PASS (0.017s)
Total:        23 tests ✅ PASS
```

#### Files Modified for D11
| File | Lines | Change |
|------|-------|--------|
| `pkg/ioc/migrations/004_multi_tenant.sql` | 104 | Created |
| `pkg/ioc/types.go` | +1 | Added `TenantID` field to `IOC` |
| `pkg/ioc/postgres_store.go` | +50 | Added `TenantContext`, tenant filtering |
| `pkg/ioc/store.go` | +20 | Added tenant filtering to in-memory store |
| `pkg/rbac/types.go` | +3 | Added `TenantID` to Agent/AgentSession/UserSession |
| `pkg/rbac/postgres_store.go` | +80 | Added `RBACTenantContext`, tenant filtering |
| `pkg/rbac/manager.go` | +30 | Updated to pass tenant context |
| `pkg/license/postgres_cache.go` | +60 | Added `LicenseTenantContext`, tenant-scoped cache |
| `pkg/license/license.go` | +40 | Added context helpers, tenant context propagation |
| `pkg/persistence/postgres_storage_backend.go` | +6 | Added `AuditTenantContext` |
| `plans/D11-MULTI-TENANT-PLAN.md` | 277 | Created implementation plan |
| `pkg/ioc/tenant_isolation_test.go` | 388 | Created (7 tests) |
| `pkg/rbac/tenant_isolation_test.go` | 399 | Created (7 tests) |
| `pkg/license/tenant_isolation_test.go` | 263 | Created (9 tests) |

#### Impact
- ✅ **Professional tier GA unblocked**: Multi-tenant isolation verified
- ✅ **Backward compatible**: All existing deployments work (empty tenant_id)
- ✅ **Admin override**: Admin users can see cross-tenant data for dashboards/auditing
- ✅ **Zero breaking changes**: All tenant context parameters are optional variadic
- ✅ **All tests pass**: 67/67 test packages passing (5,990 individual tests)

### D14: ACP Protocol Module — First-Class Platform Status ✅ COMPLETE (2026-07-20)

**ACP is now a first-class protocol guard at parity with A2A: platformconfig-integrated, flag-gated, threat-modeled, and CHANGELOG-documented.**

#### What was implemented (D14)
- **`pkg/acp/` (4346 LOC, 90.2% coverage, 184 tests)** — already shipped in Sprint 15:
  - `acp_types.go` — Full ACP message types (Message, AgentRequest, AgentResponse, ClientRequest, ClientResponse, capabilities, terminal, fs, http, auth, session)
  - `acp_guard.go` — Response scanner with PII/secret detection, per-session rate limiting, method blocking
  - `acp_hmac.go` — HMAC-SHA256 message integrity with constant-time comparison and 5-min timestamp tolerance
  - `acp_capabilities.go` — Fail-closed capability enforcer (terminal, fs, http, env)
  - `acp_config.go` + `acp_config_loader.go` — YAML/env config with blocked method list
  - `acp_middleware.go` — HTTP middleware with XSS protection, request/response scanning
  - `acp_metrics.go` — Prometheus metrics (8 metric types: messages, HMAC verifications, rate limits, scan duration, PII/secrets detected, blocked methods, sessions, guard enabled)
  - `acp_lab_test.go` — Keycloak integration tests
  - `acp_wrap_test.go` — Middleware wrap tests
  - `schema.json` — 159K ACP spec schema
  - `doc.go` — Package documentation

#### D14 integration work (this session)
- **`pkg/platformconfig/config.go`** — Added `ACPConfig` struct (parity with A2AConfig)
- **`configs/aegisgate-platform.yaml`** — Added `acp:` section (defaults to enabled)
- **`cmd/aegisgate-platform/main.go`** — Gated ACP middleware on `cfg.ACP.Enabled` (parallel to A2A pattern)
- **`pkg/platformconfig/coverage_round2_test.go`** — Added 5 ACP tests:
  - `TestDefaultConfig_ACPDefaults` — Default config has ACP disabled with `configs/acp.yaml` path
  - `TestApplyEnvOverrides_ACPEnabledTrue` — `AEGISGATE_ACP_ENABLED=true` works
  - `TestApplyEnvOverrides_ACPEnabledFalse` — `AEGISGATE_ACP_ENABLED=false` works
  - `TestApplyEnvOverrides_ACPConfigFile` — `AEGISGATE_ACP_CONFIG_FILE` override works
  - `TestLoadFromFile_ACPSection` — YAML loading of `acp:` section works

#### Threat Model
- **`plans/THREAT-MODEL.md`** — Added Section 2.5 "ACP Protocol Threats (STRIDE)" with 12 STRIDE threats:
  - **S** (Spoofing): ACP-S-01 (impersonation), ACP-S-02 (origin spoofing)
  - **T** (Tampering): ACP-T-01 (content tampering), ACP-T-02 (capability forgery), ACP-T-03 (blocked method bypass)
  - **R** (Repudiation): ACP-R-01 (denial of sent message)
  - **I** (Information Disclosure): ACP-I-01 (data exfil), ACP-I-02 (credential leakage)
  - **D** (DoS): ACP-D-01 (resource exhaustion), ACP-D-02 (session flooding)
  - **E** (Elevation): ACP-E-01 (capability escalation), ACP-E-02 (tier bypass)
- Updated CVSS scoring table with 4 ACP entries (CVSS 8.2–9.0)
- Updated Mitigation Verification Matrix with 7 ACP control mappings
- Updated Component Inventory with ACP Communication row
- Updated Executive Summary to mention 5 security pillars

#### Test Results
```
pkg/acp           184 tests  ✅ PASS (0.196s) — 90.2% coverage
pkg/platformconfig 5 new tests ✅ PASS — 97.6% coverage
Full suite:        65/65 packages passing, 0 failures
```

#### Files Modified for D14
| File | Change |
|------|--------|
| `pkg/platformconfig/config.go` | +18 lines: `ACPConfig` struct, `Config.ACP` field, defaults, env overrides |
| `pkg/platformconfig/coverage_round2_test.go` | +71 lines: 5 ACP tests |
| `configs/aegisgate-platform.yaml` | +3 lines: `acp:` section |
| `cmd/aegisgate-platform/main.go` | +18 lines: ACP gated on `cfg.ACP.Enabled` |
| `plans/THREAT-MODEL.md` | +50 lines: Section 2.5 ACP STRIDE, 4 CVSS, 7 mitigations, 1 component |
| `plans/D14-ACP-PLAN.md` | 262 lines: Created implementation plan |
| `plans/DEFERRED-ITEMS.md` | D14 marked complete |
| `plans/SESSION-HANDOFF-2026-07-20.md` | D14 summary added |

#### Impact
- ✅ **5-protocol coverage complete**: HTTP, MCP, A2A, ACP, RESPONSE (matches the D14 strategic goal)
- ✅ **Parity with A2A**: ACP now has platformconfig integration, env overrides, and main.go flag-gating
- ✅ **Threat model complete**: ACP documented in same depth as A2A (12 STRIDE threats, 7 mitigations)
- ✅ **All tests pass**: 65/65 packages passing, 5 new platformconfig tests, 0 regressions
- ✅ **Backward compatible**: ACP defaults to enabled in `aegisgate-platform.yaml` but can be disabled via config or env

### D16: Trust Framework — First-Class Platform Status (6th Pillar) ✅ COMPLETE (2026-07-20)

**The Trust Framework is the 6th pillar. Audit brought 8 pre-existing packages to first-class platform status — parity with A2A and ACP.**

#### What already existed (8 packages, ~8,500 LOC)
The Trust Framework was substantially built across 8 packages before D16:
- `pkg/trust/` (1,038 LOC) — Manager, session, hooks, HTTP API, 88.9% coverage
- `pkg/trust/identity/` (674 LOC) — ECDSA P-256 agent identity + registry, 90.9% coverage
- `pkg/trust/contract/` (853 LOC) — Capability contracts + enforcement, 88.8% coverage
- `pkg/trust/score/` (973 LOC) — Trust score engine + baseline + anomaly, 88.8% coverage
- `pkg/trust/attestation/` (570 LOC) — Legacy Ed25519 trust attestations, 89.3% coverage
- `pkg/trust/dashboard/` (276 LOC) — Real-time agent map, 87.8% coverage
- `pkg/attestation/` (986 LOC) — **Envelope primitive** (frozen 2026-06-15, ECDSA P-256), 85.4% coverage
- `pkg/digest/` (1,505 LOC) — CISO Posture Digest (PDF + signed envelope), 81.8% coverage

#### D16 integration work (this session)
- **`pkg/platformconfig/config.go`** — Added `TrustConfig` struct (parity with A2AConfig/ACPConfig)
  - `Enabled bool` — opt-in (default: false)
  - `ConfigFile string` — path to trust.yaml (default: "configs/trust.yaml")
  - `RequireLicense bool` — gate behind license middleware Professional+ (default: true, per locked decision Q3)
- **`configs/aegisgate-platform.yaml`** — Added `trust:` section (enabled: true, config_file: configs/trust.yaml, require_license: true)
- **`cmd/aegisgate-platform/main.go`** — Wired Trust HTTP API at `/api/v1/trust/*`:
  - Gated on `cfg.Trust.Enabled` (parallel to A2A/ACP pattern)
  - When `cfg.Trust.RequireLicense=true` and `licenseMgr` exists, wrapped in `license.NewLicenseMiddleware(licenseMgr).RequireTier(tier.TierProfessional)`
  - When disabled, returns `{"status": "disabled", "reason": "trust framework not configured"}`
- **`pkg/platformconfig/coverage_round2_test.go`** — Added 6 Trust tests:
  - `TestDefaultConfig_TrustDefaults` — Enabled=false, ConfigFile=configs/trust.yaml, RequireLicense=true
  - `TestApplyEnvOverrides_TrustEnabledTrue` — AEGISGATE_TRUST_ENABLED=true works
  - `TestApplyEnvOverrides_TrustEnabledFalse` — AEGISGATE_TRUST_ENABLED=false works
  - `TestApplyEnvOverrides_TrustConfigFile` — AEGISGATE_TRUST_CONFIG_FILE override works
  - `TestApplyEnvOverrides_TrustRequireLicense` — AEGISGATE_TRUST_REQUIRE_LICENSE=false works
  - `TestLoadFromFile_TrustSection` — YAML loading of `trust:` section works

#### Threat Model
- **`plans/THREAT-MODEL.md`** — Added Section 2.6 "Trust Framework Threats (STRIDE)" with 10 STRIDE threats:
  - **S** (Spoofing): TRF-S-01 (identity impersonation), TRF-S-02 (trust score spoofing)
  - **T** (Tampering): TRF-T-01 (trust score tampering), TRF-T-02 (capability contract forgery)
  - **R** (Repudiation): TRF-R-01 (denial of behavior)
  - **I** (Information Disclosure): TRF-I-01 (agent identity disclosure)
  - **D** (DoS): TRF-D-01 (anomaly detection bypass), TRF-D-02 (session flooding)
  - **E** (Elevation): TRF-E-01 (capability escalation via forged contract), TRF-E-02 (tier bypass)
- Updated CVSS scoring table with 4 Trust entries (CVSS 8.5–9.0)
- Updated Mitigation Verification Matrix with 7 Trust control mappings
- Updated Component Inventory with Trust Framework row
- Updated Executive Summary to mention 6 security pillars

#### Test Results
```
pkg/trust                  88.9% coverage  ✅
pkg/trust/attestation      89.3% coverage  ✅
pkg/trust/contract         88.8% coverage  ✅
pkg/trust/dashboard        87.8% coverage  ✅
pkg/trust/identity         90.9% coverage  ✅
pkg/trust/score            88.8% coverage  ✅
pkg/attestation            85.4% coverage  ✅ (envelope primitive, frozen 2026-06-15)
pkg/platformconfig         97.8% coverage  ✅ (+6 new Trust tests)
Full suite: 65/65 packages passing, 0 failures
```

#### Files Modified for D16
| File | Change |
|------|--------|
| `pkg/platformconfig/config.go` | +30 lines: `TrustConfig` struct, `Config.Trust` field, defaults, env overrides |
| `pkg/platformconfig/coverage_round2_test.go` | +90 lines: 6 Trust tests |
| `configs/aegisgate-platform.yaml` | +4 lines: `trust:` section |
| `cmd/aegisgate-platform/main.go` | +30 lines: Component 6 wiring (Trust HTTP API gated on cfg.Trust.Enabled) |
| `plans/THREAT-MODEL.md` | +60 lines: Section 2.6 Trust STRIDE, 4 CVSS, 7 mitigations, 1 component |
| `plans/DEFERRED-ITEMS.md` | D16 marked complete in main table + completed items list |
| `plans/TRUST-FRAMEWORK-AUDIT.md` | Created (284 lines, full implementation plan) |
| `CHANGELOG.md` | D16 entry in v3.4.0+ Unreleased section |

#### Impact
- ✅ **6-pillar coverage complete**: HTTP, MCP, A2A, ACP, RESPONSE, **Trust Framework**
- ✅ **Parity with A2A/ACP**: TrustConfig in platformconfig, env overrides, main.go flag-gating
- ✅ **Threat model complete**: 10 STRIDE threats, 7 mitigations documented
- ✅ **All tests pass**: 65/65 packages, 6 new platformconfig tests, 0 regressions
- ✅ **Backward compatible**: Trust defaults to disabled in `aegisgate-platform.yaml` (opt-in)
- ✅ **License-gated**: Professional+ tier enforcement via Q3 decision (configurable via `require_license: false`)

### D19: Attestation + Posture HTTP Endpoints ✅ COMPLETE (2026-07-20)

**Closes audit Finding #8 (P1 High). All 9 v3.4.0+ features are now wired as both CLI and HTTP.**

The 2 v3.4.0+ features that had CLI-only exposure (attestation, posture)
now have full HTTP endpoints on the dashboard mux.

#### What was done (D19)

**`cmd/aegisgate-platform/posture_http.go`** (new, 145 lines):
- `GET /api/v1/posture` — JSON report (compact)
- `GET /api/v1/posture/verbose` — JSON report (verbose shape)
- `GET /api/v1/posture/text` — plain-text report (matches `aegisgate status` output)
- All 3 routes require auth
- Reuses the existing `runPostureCheck()` helper from posture_subcommand.go
- Supplants the un-wired `handlePostureAPI` stub

**`cmd/aegisgate-platform/attestation_http.go`** (new, 152 lines):
- `POST /api/v1/attestation/verify` — Verify envelope (offline, embedded pubkey)
- `POST /api/v1/attestation/verify-online` — Verify with public key fetch from `/.well-known/`
- Both routes require auth
- Reuses the existing `verifyResult` and `buildVerifyResultJSON` from attestation_subcommand.go

**`cmd/aegisgate-platform/main.go`** (+21 lines): added `wirePostureHandlers` and `wireAttestationHandlers` calls in the dashboard mux section, with log lines.

#### Tests (9 new, all PASS)
- 5 posture tests: `TestHandlePostureJSON_MethodNotAllowed`, `TestHandlePostureJSON_OK`, `TestHandlePostureVerbose_OK`, `TestHandlePostureText_OK`, `TestHandlePostureText_NotFound`
- 4 attestation tests: `TestHandleAttestationVerify_MethodNotAllowed`, `TestHandleAttestationVerify_InvalidJSON`, `TestHandleAttestationVerifyOnline_MethodNotAllowed`, `TestHandleAttestationRoutes_Registered`

#### Test Results
```
pkg/acp + pkg/attestation + pkg/digest + pkg/evidence + pkg/posture + ...
+ cmd/aegisgate-platform: 97 tests PASS
Full suite: 66/66 packages passing, 6,035 individual tests PASS, 0 FAIL
```

#### Impact
- ✅ **All 9 v3.4.0+ features now have HTTP endpoints** (previously 7/9)
- ✅ **Auditor workflow no longer requires CLI access** — `POST /api/v1/attestation/verify` accepts an envelope over HTTP
- ✅ **Posture check exposed for CI gates** — `GET /api/v1/posture/text` returns the same output as `aegisgate status`
- ✅ **Closes audit Finding #8** (P1 High) and improves strategic posture for H4 pentest
- ✅ **9 new tests with no regressions** (66/66 packages still pass)

### What's new on `main`

#### The envelope primitive (the v3.4.0+ cryptographic backbone)

A single, frozen, well-tested cryptographic primitive (`pkg/attestation/`, 18 tests, frozen 2026-06-16) that wraps any domain-specific payload with a tamper-evident, third-party-verifiable binding. **One envelope, 9 features, 0 duplication.**

- **4 lifecycle operations** (frozen 2026-06-16, Council of Mine 8/8 unanimous): `Sign`, `Verify`, `VerifyWithKey`, `VerifyOnline`
- **9-reason error taxonomy** (`ReasonMalformed`, `ReasonUnknownType`, `ReasonInvalidSubject`, **`ReasonSignatureInvalid`** (CRITICAL), `ReasonKeyMismatch`, `ReasonExpired`, `ReasonNotYetValid`, `ReasonPublicKeyFetch`, `ReasonAlgorithmUnsupported`)
- **8 registered types** (all used by the 9 v3.4.0+ features): `TypeEvidenceManifest`, `TypeEvidenceCrossProtocol`, `TypeEvaluatorRun`, `TypeAIBOM`, `TypeAgentIntent`, `TypePromptCacheAttestation`, `TypeCVEEntry`, `TypeDigest`
- **9 URI-style subject kinds** (`aegisgate://<kind>/<id>` grammar): `manifest`, `evaluation`, `deployment`, `intent`, `prompt`, `cve`, `digest`, `agent`, `ioc`
- **Canonical CLI verb:** `aegisgate attestation verify envelope.json` → `VALID` / `INVALID: signature does not verify`
- **JCS canonicalization** (RFC 8785) from scratch, ~200 LOC of stdlib, zero new external dependencies

#### The 5 Tier 5 features (built on the envelope)

| Feature | Package | Coverage | Tests | Wire format |
|---|---|---|---|---|
| **AR-EaaS** (Adversarial Robustness Evals-as-a-Service) | `pkg/evaluator/` | 92.0% | 38 | `TypeEvaluatorRun` = `evaluator.run.v1`, subject `aegisgate://evaluation/<run-id>`, issuer `ar-eaas:shortfp:<16-hex>:<key-id>` |
| **AIBOM** (AI Bill of Materials, CycloneDX 1.6 + AI ext) | `pkg/aibom/` | 86.8% | 38 | `TypeAIBOM` = `aibom.cyclonedx.v1`, subject `aegisgate://deployment/<uuid>`, issuer `aibom:shortfp:<16-hex>:<key-id>` |
| **Agent Intent Signing** (A2A intent binding) | `pkg/agentintentsign/` | 91.6% | 53 | `TypeAgentIntent` = `a2a.intent.v1`, subject `aegisgate://intent/<uuid>`, issuer `a2a-intent:shortfp:<16-hex>:<key-id>:<sanitized-agent-id>` (5 components, tail-matchable) |
| **Prompt Cache Poisoning Detection** | `pkg/promptcache/` | 92.2% | 74 | `TypePromptCacheAttestation` = `promptcache.attestation.v1`, subject `aegisgate://prompt/<sha256-hex>`, issuer `promptcache:shortfp:<16-hex>:<key-id>` |
| **CVE-for-AI Entry Publisher** | `pkg/cve/` | 92.0% | 82 | `TypeCVEEntry` = `cve.entry.v1`, subject `aegisgate://cve/AEGIS-YYYY-NNNN`, issuer `cve:shortfp:<16-hex>:<key-id>`, **Enterprise-only** for publish |

#### The 2 Tier 3 features

| Feature | Package | Coverage | Tests | Notes |
|---|---|---|---|---|
| **PDF Generator** (from-scratch PDF 1.4) | `pkg/pdf/` | **95.5%** | 50+27+2 | v0.2 branding (header banner + URL + ID + period in footer); **zero new external dependencies** (~750 LOC of stdlib) |
| **SOC Incident-Timeline View** | `pkg/soc/` | **100%** | 25 | `GET /api/v1/soc/incidents/{id}/timeline` with Go 1.22+ native `{id}` path variable |

#### The 2 Tier 4 features (CISO Digest + reporting pipeline)

| Feature | Package | Coverage | Tests | Notes |
|---|---|---|---|---|
| **CISO Posture Digest** | `pkg/digest/` | **81.8%** | 40+14 | v0.2 wired with real data sources (PostureSource + IOCSource + AuditLogSource + AuditSource); branded PDF + signed envelope; Professional+ tier gated |
| **Reporting Pipeline** | `pkg/digest/sources.go` + `pkg/reporting/` | (integrated) | (covered by 601) | Source interface + 4 adapters |

#### 7 self-review files (`docs/reviews/`)

Every feature has a self-review documenting the issues found and fixed. **Cumulative: 44 issues found and fixed** across 7 review files:

- `TODO-301-REVIEW.md` — 12 issues (AR-EaaS)
- `TODO-302-REVIEW.md` — 5 issues (AIBOM)
- `TODO-303-REVIEW.md` — 6 issues (Agent Intent Signing)
- `TODO-304-REVIEW.md` — 6 issues (Prompt Cache Poisoning)
- `TODO-305-REVIEW.md` — 5 issues (CVE-for-AI)
- `TODO-501-502-REVIEW.md` — 6 issues (PDF + SOC)
- `TODO-601-602-REVIEW.md` — 4 issues (CISO Digest + pipeline)

#### 3 v0.2 wiring fixes (this session's work, 2026-06-18)

- **CISO Digest data sources** (`a5ad71f fix(digest): wire CISO Digest data sources (v0.2 wiring)`) — added `AuditLogSource` (reads from `pkg/logging.RingBuffer` via `CountByFramework`, `CountByProtocol`, and a new `SnapshotBetween` method); fixed the merge logic in `builder.go` (the v0.1 last-write-wins approach was a v0.2 bug that clobbered the IOC totals); wired CLI to use real in-memory stores and HTTP via a new `WireDigestDeps` struct. **14 new tests**; coverage 76.0% → 81.8%.
- **PDF branding** (`9b0ca8f feat(pdf): v0.2 branding — header + enhanced footer (TODO-501 v0.2)`) — added 5 new fields to `RenderRequest` (`Header`, `HeaderSubtitle`, `FooterURL`, `FooterIncludeID`, new `FontHeader` constant). The digest renderer now uses the new fields. **2 new tests**; coverage 95.4% → 95.5%.
- **CI fixes** (`f75b2e0 fix(ci): gofmt + exempt pkg/reporting from per-package coverage`) — 3 gofmt issues fixed; `pkg/reporting` added to `EXEMPTED_PACKAGES` in `.github/workflows/ci.yml` (the happy path of `ExportPDF` requires running the upstream reporter's scheduler, which is a process-level test; the error paths and `ExportPDFAdHoc` are tested).

#### Phase 1: PostgreSQL Persistence Backend (D1)

- **IOC Store** (`pkg/ioc/`, PostgreSQL-backed) — persistent IOC storage with Snapshot, Query (indexed by SourceProvider), and domain hash verification. Migrations 001–002 auto-applied on startup.
- **Audit Log** (`pkg/persistence/`, PostgreSQL-backed) — persistent audit log storage replacing in-memory ring buffer for Professional+ tier. Migration 003 auto-applied.
- **RBAC + License** (`pkg/rbac/` + `pkg/license/`) — PostgreSQL-backed RBAC store and license cache for Professional+ tier, with in-memory fallback for Community tier.
- **Testlab Integration** — Docker Compose PostgreSQL service with health checks, automated integration test runner, CI-compatible `DATABASE_URL`.

#### Phase 2: Lens-Platform Schema Alignment

- **157 categories** across 6 facets (PII, Secrets, XSS, Prompt Injection, Toxicity, Compliance) — expanded from the original 6 to match Lens v0.2.0's full detection schema.
- **8 IOC types** — aligned with Lens v0.2.0's detection output (PII leak, secret exposure, XSS, prompt injection, toxic output, compliance violation, hallucination, model integrity erosion).
- **Category-facet-index** — `categoryFacetIndex` maps every category to its parent facet for validation and grouping.

#### Phase 3: Lens Telemetry Bridge

- **FP-Report Bridge** (`pkg/lensbackend/fp_report.go`, 234 LOC) — accepts Lens v0.2.0's 4-field format (hashed_domain, category, severity, action), validates input, and bridges to full Event schema with defaults. 14 unit tests + 1 end-to-end test (414 LOC).
- **CORS Middleware** (`pkg/lensbackend/server.go`) — preflight support for browser extension cross-origin requests. All 5 endpoints wrapped.
- **Main Binary Wiring** (`cmd/aegisgate-platform/main.go`) — Lens backend mounted at `/api/v1/lens/*` on proxy mux. Feature-gated to Professional+ tier. CLI flags and env vars for configuration.
- **Lens Extension** (`aegisgate-lens/src/`) — "Connect to Platform" UI in popup with healthz connectivity test and MV3 `optional_host_permissions`. `SET_BACKEND_URL` message propagates URL to service worker with automatic queue drain.

#### Phase 4: SIEM Dispatcher Wiring (D15)

- **SIEM Config** (`pkg/platformconfig/config.go`) — 6 YAML-able structs with defaults and env var overrides. Supports 11 platforms: Splunk, Elasticsearch, QRadar, Sentinel, SumoLogic, LogRhythm, CloudWatch, SecurityHub, ArcSight, Syslog, Custom.
- **Main Binary Wiring** — SIEM dispatcher polls `evidence.EventSource`, translates to `siem.Event`, forwards to `siem.Manager`. Feature-gated to Professional+ tier.
- **Health Check** — SIEM status added to `/health` endpoint (enabled, healthy, platforms, events_forwarded, events_dropped).
- **Dashboard API** — `GET /api/v1/siem/status` (auth-required) shows dispatcher stats and platform config.

#### Phase 5: IOC Query Performance

- **Indexed Query** (`pkg/ioc/store.go`) — `bySP` index maintained in `Observe()` for O(k) SourceProvider lookups. New `Query(IOCQuery)` method with fast-path indexed lookup and slow-path full scan.
- **25× latency improvement** for `/api/v1/lens/check` — 9.2ms → 365μs (10K IOC benchmark).
- **10× memory reduction** — 1.76MB/call → 180KB/call for SourceProvider queries.

#### Engineering hygiene

- **Zero new external dependencies** added across the 9-feature Tier 5+3+4 sprint. `go.mod` has the same 8 direct deps it had at the start of the v3.3.0-beta.2 release (jwt, uuid, prometheus, oauth2, yaml, stretchr/testify, plus 2 indirect).
- **5,990 tests passing under -race** across 67 platform packages (was 5,484).
- **Project-wide coverage 91%+** with all 67 measured packages ≥80% (CI floor).
- **24 design patterns** documented in the 7 review files, applied consistently across all 9 features.
- **The platform and website are now in sync with the remote.** The CVE-for-AI portal is live at [aegisgatesecurity.io/cve/](https://aegisgatesecurity.io/cve/); the security.txt is live at [aegisgatesecurity.io/.well-known/security.txt](https://aegisgatesecurity.io/.well-known/security.txt).

### What's still on the roadmap (not in v3.4.0+)

- **v3.4.0 GA** — gated on H1 (legal review) + H4 (paid pentest); expected Q3 2026
- **The 3 v0.1 → v0.2 transitions** (now closed): the 3 v0.1 wiring fixes are done. What remains is the **v0.2 → v1.0** transition (multi-tenant, scheduled digests, custom branding per customer) — deferred to v0.5/v1.0
- **The static CVE portal** — the Go package + the website portal are both shipped. The curated CVE entry browser (v0.3) and the auto-publish workflow are deferred
- **The Tier 6+ roadmap** (speculative): real-time SOC analyst AI copilot, PentestGPT, AI-specific SOAR, CNA with MITRE

### Commits on `main` since v3.3.0-beta.2

```
f3a5101 fix(ci): gofmt + exempt pkg/reporting from per-package coverage
d98552a docs(readme): add v3.4.0+ 'What's New on main' section; fix 5->6 pillars
455930a chore(deps): bump alpine from `5b10f43` to `a2d49ea` (#67)   [dependabot]
fa933d9 chore(deps): bump golang from `f23e8b2` to `7a3e500` (#66)   [dependabot]
9b0ca8f feat(pdf): v0.2 branding — header + enhanced footer (TODO-501 v0.2)
a5ad71f fix(digest): wire CISO Digest data sources (v0.2 wiring)
f343b89 fix(pdf): wire Tier 4 word-wrap + Unicode extensions into existing code
398d8b2 docs(tier-4): add TODO-601+602 self-review
7426720 TODO-601 + TODO-602: CISO Posture Digest + reporting pipeline (Tier 4)
aa98ae3 docs(tier-3): add TODO-501+502 self-review
193d016 TODO-501 + TODO-502: PDF generation + SOC incident-timeline view (Tier 3)
bada988 docs(cve): add TODO-305 self-review
fa5f6ac TODO-305: CVE-for-AI Entry Publisher v0.1
8acf7c1 docs(promptcache): add TODO-304 self-review
4bbe57c TODO-304: Prompt Cache Poisoning Detection v0.1
c08aff4 docs(evaluator): add TODO-301 review (was written but not committed)
c4b41ad fix(agentintentsign): apply TODO-303 review fixes (C1, C2, M1, M2, M3, m1)
e1c4a69 TODO-303: Agent Intent Signing (A2A intent binding) v0.1
04fa686 fix(aibom): apply TODO-302 review fixes (C1, C2, M1, M2, m2)
332f0e2 TODO-302: AIBOM — AI Bill of Materials (CycloneDX 1.6 extension) v0.1
ee2ba00 fix(evaluator): apply TODO-301 review fixes (C1-C3, M1-M2, m1-m7)
13ab18e TODO-301: AR-EaaS — Adversarial Robustness Evals-as-a-Service (v0.1)
fe59f2e Phase 5: /check endpoint performance — indexed Query with 25× speedup
c883e25 Phase 4 (D15): SIEM config wiring — platformconfig, main.go, health check, status endpoint
9c6e218 Phase 3B: End-to-end integration test — FP-report → IOC → /check verdict
98e9db5 Phase 3A: Lens telemetry routing — FP-report bridge + CORS + main binary wiring
2ab964d Phase 2A/2B/2C: Lens-Platform schema alignment — 157 categories, 6 facets, 8 IOC types
3a48737 D1 Phase 1D: testlab PostgreSQL integration tests + docker-compose DATABASE_URL
755704b D1 Phase 1C (main.go wiring): connect PostgresStore to RBAC, license, and persistence
58e1638 D1 Phase 1C (wiring): dual-backend RBAC Manager + license cache with PostgreSQL dispatch
7ce1b0e CI: exempt pkg/rbac and pkg/license from coverage floor (PostgreSQL-backed code requires live DB)
099ea6b D1 Phase 1C: PostgreSQL session/license state — RBAC store, license cache, migration 003
```

## [3.3.0-beta.2] - 2026-06-08 - EU AI Act Module Integration Fix 🩹

> **Status: Beta.2 hotfix.** v3.3.0-beta.1 was tagged on 2026-06-08, but a release-integrity review on the same day discovered that **5 commits implementing the EU AI Act work (Phases 1.1, 1.2, 1.3) had never been merged to `main`**. The v3.3.0-beta.1 tag pointed at a commit on `main` that did **not** contain the EU AI Act sub-package, the customer 1-pager, the marketing site update, or the gitignore enforcement. The CHANGELOG claimed the module was included; the code was not. **v3.3.0-beta.2 fixes this integrity gap by merging the missing work into `main` and re-tagging.**

This is a **code-content fix, not a security fix**. No CVE, no vulnerability, no leaked data. The missing work was always present on a feature branch (`fix/untrack-and-purge-leaked-plans`) and has now been merged. After this beta.2, the actual `pkg/compliance/eu-ai-act/` sub-package matches the v3.3.0-beta.1 CHANGELOG description.

### What changed (vs. v3.3.0-beta.1)

| Area | Beta.1 | Beta.2 |
|---|---|---|
| `pkg/compliance/eu-ai-act/` (82 controls) | ❌ missing from `main` | ✅ **NOW INCLUDED** |
| `docs/compliance/eu-ai-act.md` (customer 1-pager) | ❌ missing from `main` | ✅ **NOW INCLUDED** |
| `docs/compliance/eu-ai-act-mapping.md` (full mapping) | ❌ missing from `main` | ✅ **NOW INCLUDED** |
| `content/pricing.md` / `content/tech.md` / `content/changelog.md` | ❌ missing from `main` | ✅ **NOW INCLUDED** |
| `docs/website/index.html` (EU AI Act section + test banner) | ❌ old version | ✅ **UPDATED** |
| `.githooks/pre-commit` (plans/ + legal-docs/ guard rail) | ❌ missing from `main` | ✅ **NOW INCLUDED** |
| `.gitignore` policy header (12 lines, no-force-add rule) | ❌ minimal | ✅ **EXPANDED** |
| `gitleaks` CI job (licensed) | ✅ present (re-enabled today) | ✅ present (unchanged) |
| 15 P3/P4 golangci-lint issues | ✅ fixed (commit `8b69aa2`) | ✅ fixed (unchanged) |

### Highlights

#### Repository hygiene (2026-06-07 → 2026-06-08)

The fix/... branch's `.gitignore` policy header and `.githooks/pre-commit` script are now active on `main`. Any future attempt to `git add` a file under `plans/` or `legal-docs/` is blocked at the local hook level. This completes the **22-file history purge** started in v3.3.0-beta.1 (the purge itself happened on the v3.3.0-beta.1 commit `ffff4c1`; the enforcement tooling is now restored).

#### EU AI Act sub-package (Phase 1.1)

`pkg/compliance/eu-ai-act/` adds 82 `RegisterControl` calls across 8 categories, mirroring the HIPAA sub-package pattern. Nine controls have automated `CheckFunc` implementations (Art 5 prohibited practices, Art 9 risk management, Art 11 technical documentation, Art 12 automatic logging, Art 13 transparency, Art 14 human oversight, Art 15 accuracy/robustness, Art 15 data-poisoning mitigation, AI-001 prompt injection). The remaining 73 are manual review items, consistent with HIPAA's automated/manual mix. Gated by `ModuleEUAIAct` → `Professional+` tier, $99/mo, matching HIPAA/PCI pricing convention.

#### EU AI Act documentation (Phase 1.2)

Two new files in `docs/compliance/`:
- `eu-ai-act.md` (104 lines, customer 1-pager) — scope, tier requirement, pricing, 8-category coverage summary, Article-by-Article walkthrough, auditor evidence checklist
- `eu-ai-act-mapping.md` (438 lines, internal mapping) — 82-control table with severity, Article reference, auto-check eligibility, Go check function name, and evidence type per row

#### Website/marketing update (Phase 1.3)

`docs/website/index.html` updated with the v3.3.0 EU AI Act callout section (3 feature cards). `content/pricing.md`, `content/tech.md`, and `content/changelog.md` are the new source-of-truth files for the website regeneration. Buy buttons remain in their beta.1 state (4 live + 6 hidden) — no change to the visible website behavior.

### Verification

- ✅ `go build ./...` PASS
- ✅ `go test ./pkg/...` PASS (all packages, 0 failures)
- ✅ `golangci-lint run` PASS (0 issues, unchanged from beta.1's lint-fix commit `8b69aa2`)
- ✅ Security workflow PASS (govulncheck, gosec, trivy, gitleaks, trufflehog, sbom — all green)
- ✅ `git log --oneline` confirms 5 commits are now reachable from `main`

### Migration from v3.3.0-beta.1

This is a **drop-in replacement**. No config changes, no API changes, no schema changes. To upgrade:

```bash
docker pull ghcr.io/aegisgatesecurity/aegisgate-platform:v3.3.0-beta.2
```

If you deployed v3.3.0-beta.1 with the EU AI Act code expected to be present: that deployment was always incomplete; re-deploy with v3.3.0-beta.2 to get the actual module.

### Still beta

Like v3.3.0-beta.1, **this is a beta release, not a commercial launch**. The first paying customer remains a v3.4.0+ milestone. Counsel review (Phase 4 docs) and the v3.3.1 paid pentest are still pending. The Professional+ tier and 6 module buy buttons remain hidden in the website UI.

---

## [3.3.0-beta.1] - 2026-06-08 - EU AI Act Module + Beta Readiness (Beta)

> **Status: Beta-ready.** v3.3.0-beta.1 is the first beta release of v3.3.0. It adds the EU AI Act as the 7th compliance module (82 controls across 8 categories), ships a minimum-viable legal kit (6 v2.0 customer-facing docs + 1 Beta User Agreement), and includes a self-attested security hardening pass with 7-tool local validation. **This is a beta release, not a commercial launch** — the first paying customer is a v3.4.0+ milestone. Professional+ tier and the 6 module buy buttons are intentionally hidden in the v3.3.0-beta.1 web UI (see Phase 3.1 hardening below).

### Highlights

#### EU AI Act Compliance Module (Phase 1.1, 2026-06-06)

The 7th compliance module adds 82 controls across 8 categories of the EU AI Act. The sub-package is at `pkg/compliance/eu-ai-act/` and is gated by the existing license + module framework. Customers can enable EU AI Act reporting on Professional+ tier with a single Stripe checkout click, following the same instant-activation pattern as the existing 6 modules.

| Category | Controls |
|---|---|
| Article 5 (Prohibited Practices) | 8 |
| Article 9 (Risk Management) | 10 |
| Article 10 (Data Governance) | 8 |
| Articles 11+12 (Technical Docs + Logging) | 10 |
| Articles 13+14 (Transparency + Human Oversight) | 14 |
| Article 15 (Accuracy/Robustness/Cyber) | 12 |
| Articles 51-55 (Post-Market Monitoring) | 10 |
| AI-* (Foundation Model Controls) | 10 |
| **Total** | **82** |

The customer-facing documentation is at `docs/compliance/eu-ai-act.md` (1-page overview) and the per-control mapping is internal to the AegisGate Security team.

#### Repository hygiene (2026-06-07)

The public repo's history was rewritten to remove 22 internal-only files (1 `plans/` file in the current tree plus 21 in orphan history) that were reachable via `git log --all --reflog`. None of these files belong in a public open-source repo — the `plans/` files contained AegisGate Security LLC's commercial strategy, and the `legal-docs/` files contained draft legal documents.

The cleanup is **enforced going forward** by:
- A 12-line policy header in `.gitignore` explaining the rationale and a hard `# NEVER \`git add -f\`` directive
- A new committed `.githooks/pre-commit` script that blocks any commit staging files under `plans/`, `legal-docs/`, or any internal wildcard pattern
- `core.hooksPath = .githooks` set in the local repo config (defense in depth — even if a future contributor reverts the hook, `.gitignore` still blocks the file)
- `git filter-repo` rewriting the history to remove all 22 leaked files and their blobs
- The `v3.2.0` GPG-signed tag re-signed at the new SHA (release commit content is byte-identical to the original; shields.io, GitHub Releases, and container tags all continue to work)

A fresh clone of the public repo now contains 0 `plans/` or `legal-docs/` files at all 3 verification layers (tree, history, blobs).

#### Security Posture Self-Attestation (Phase 3, 2026-06-08)

A 7-tool local self-attestation was performed on the v3.3.0-beta.1 codebase. All raw reports are preserved at `legal-docs/21-self-attestation-v3.3.0/raw-reports/` (gitignored, internal-only) along with the self-attestation document at `legal-docs/21-self-attestation-v3.3.0/security-posture-v3.3.0.md`.

| Tool | Verdict |
|---|---|
| `gosec` (Go SAST) | ✅ 1 finding (known false positive: `SECRET_OAUTH_TOKEN` category identifier) |
| `govulncheck` (Go team dep scanner) | ✅ 0 called vulnerabilities |
| `golangci-lint` (5 linters) | ✅ 16 P1+P2 findings fixed; 15 P3+P4 deferred to v3.3.1 |
| `gitleaks` (regex secret detection) | ✅ 0 findings (was 837; `.gitleaks.toml` allowlist created) |
| `trivy fs` (CVE + misconfig + secret) | ✅ Dockerfile + K8s + 3 RSA test-fixture keys documented |
| `syft` (SBOM) | ✅ SPDX 2.3 SBOM (257 packages) |
| `nmap` (port scan) | ✅ 3 expected ports, 0 unexpected |

**Verdict: PASS for v3.3.0-beta.1.** 0 critical, 0 high-severity code vulnerabilities, 0 exposed production secrets. Pre-GA action items: review 56 non-test gitleaks findings (categorized as test fixtures + MITRE ATLAS false positives + 1 already-removed whsec); 3 RSA private keys in `upstream/` documented as test fixtures in `.trivyignore`.

#### Legal Kit (Phase 4, 2026-06-08)

Six customer-facing legal documents were finalized to v2.0 DRAFT and one new Beta User Agreement was added. All docs are gitignored in `legal-docs/` (internal-only, never committed to public repo). The corresponding public web pages are at `https://aegisgatesecurity.io/legal/`:

| Document | Lines | Web Page |
|---|--:|---|
| `02-DPA-Data-Processing-Agreement.md` (v2.0) | 222 | `/legal/dpa/` |
| `06-Cookie-Policy.md` (v2.0) | 126 | `/legal/cookies/` |
| `08-Subprocessor-List.md` (v2.0) | 148 | `/legal/subprocessors/` |
| `12-Terms-of-Service.md` (v2.0) | 363 | `/legal/terms/` |
| `13-Privacy-Policy.md` (v2.0) | 212 | `/legal/privacy/` |
| `19-Beta-User-Agreement.md` (v1.0 — NEW) | 109 | `/legal/beta-agreement/` |

All docs are marked with a uniform "self-drafted, not legal advice" header and a "Counsel Sign-Off Required" footer. Q1-Q4 (path, state, subprocessors, cookie audit) decisions applied. The 17-clause legal review framework (in `legal-docs/15-LEGAL-REVIEW-FRAMEWORK.md`) was used to apply vendor-favorable revisions to the audit-rights cap (DPA §4) and other clauses. The full per-doc analysis is preserved as `-DRAFT-ORIGINAL.md` backups.

#### v3.3.1 Hardening (Phase 3.1, 2026-06-08)

A 4-item hardening pass was applied ahead of v3.3.0-beta.1 to address the trivy misconfig findings from the self-attestation:

1. **Dockerfile base images pinned by SHA256 digest.** Both `golang:1.26.5-alpine` (builder) and `alpine` (production) are now pinned to specific digests for reproducible builds. The `alpine:latest` tag (which trivy flagged as HIGH severity) is removed.
2. **`seccompProfile.type: RuntimeDefault` added** to both pod-level and container-level `securityContext` in:
   - `deploy/k8s/manifests/03-deployment.yaml` (raw manifest)
   - `deploy/helm/aegisgate-platform/values.yaml` (Helm chart)
3. **Gitleaks CI job added** to `.github/workflows/security.yml` (now 9 jobs total). The new job uses the `.gitleaks.toml` allowlist and complements the existing TruffleHog job (regex-based vs. entropy-based detection).
4. **wget installed in production Dockerfile** for the existing HEALTHCHECK directive (the directive was present but wget wasn't installed in the minimal image — now it is).

#### Buy-Button Visibility (Website Hardening)

The Professional+ tier (2 buttons) and all 6 module buy buttons are hidden in the v3.3.0-beta.1 website with a "Available after v3.4.0" placeholder. The 4 Starter + Developer buttons remain live (sellable). This is a v3.3.0-beta-only posture; the buttons will reappear in v3.3.0-GA after counsel review and the v3.3.1 paid pentest are complete.

### Phase Status
Phase 1.1 (EU AI Act sub-package) ✅ | Phase 1.2 (docs) ✅ | Phase 1.3 (website/marketing) ✅ | Phase 2 (test-mode Buy Buttons) ⏳ | Phase 3 (security posture) ✅ | Phase 3.1 (hardening) ✅ | Phase 4 (legal kit) ✅ | Phase 5 (beta release engineering) ⏳ | Phase 5.5 (posture check) ⏳

## [3.2.0] - 2026-06-05 - Compliance Modules + Trust Framework (Released)

> **Status: Released.** v3.2.0 is the largest feature release in AegisGate's history. All 6 implementation phases (0, 1, 2, 3, 4, 5, 6, 7, 8) are complete. The `v3.2.0` GPG-signed annotated tag points at this commit; the GitHub Release is auto-built by `.github/workflows/release-v2.yml` (binary + cosign-signed container + SBOM attestation). The shields.io version badge on the website reads from the `v3.2.0` tag.

### Highlights

#### Compliance Modules (Phase 1) — _Tier add-ons_

Six billable compliance modules are now available as add-ons to any paid tier. Prices are locked from the pricing-table decision (2026-06-04) and will not change for existing customers (Q2: lock-in at purchase price forever).

| Module | Price | Required Tier | Description |
|---|---|---|---|
| HIPAA | $99/mo | Developer+ | HIPAA-compliant logging, PHI detection, BAA support |
| PCI-DSS | $99/mo | Developer+ | Payment card data detection, PCI-scoped audit logs |
| SOC 2 | $149/mo | Developer+ | SOC 2 Type II control mapping, evidence collection |
| ISO 42001 | $79/mo | Professional+ | ISO/IEC 42001 AI management system controls |
| FedRAMP | $499/mo | Professional+ | FedRAMP Moderate/High control mapping, continuous monitoring |
| FIPS 140-2/140-3 | $299/mo | Professional+ | FIPS-validated cryptography enforcement, HSM integration |

Modules are purchased via Stripe checkout and activated instantly on the customer's license via the existing webhook (Q1: instant via Stripe webhook).

**All 6 module products are now live in the Stripe dashboard** (2026-06-05). Buy buttons on the [website pricing page](https://aegisgatesecurity.io/pricing/).

#### Compliance Scan Engine (Phase 3) — _Completed 2026-06-05_

The customer-facing compliance scan engine. The scanner answers two questions the customer portal needs:

1. "Is my customer's compliance posture good right now?" — via `GET /api/v1/compliance/scan` returning per-framework Enforced/Score/ControlsTotal/ControlsEnforced/CompliancePct.
2. "What modules do I need to buy to enable X?" — via `GET /api/v1/compliance/report?framework=X` returning MissingModules and UpgradeHint.

Three HTTP endpoints, all under `/api/v1/compliance/`:

```
GET /health      -> liveness (no auth)
GET /scan        -> full ScanReport (all 9+ frameworks)
GET /report?framework=X  -> single framework detail (with aliases)
```

Framework name aliases (30+ accepted): `pci-dss`, `soc-2`, `iso 42001`, `fips 140-2`, `nist_ai_rmf`, `mitre atlas`, `owasp llm top 10`, etc. — all normalize to the canonical framework name.

**Real control counts shipped:** HIPAA module registers 13 controls, PCI module registers 21 controls. Other modules (SOC 2, ISO 42001, FedRAMP, FIPS) return 0 until their sub-packages are implemented.

#### Trust Framework — 6th Pillar (Phase 4) — _Professional+ tier_

The newest architectural pillar: continuous, per-agent cryptographic trust scoring with signed attestations. The Trust Framework gives security teams a real-time view of "is this agent behaving normally?" and "what was its score at the start vs end of this request?".

**New code:**
- `pkg/tier/tier.go` — `FeatureTrustPillar` constant (Pro+ gate)
- `pkg/trust/session.go` — per-session trust accumulator on top of `score.Engine`
- `pkg/trust/api.go` — HTTP API at `/api/v1/trust/` (7 endpoints)
- `pkg/trust/hooks.go` — opt-in `Hooks` bridge for protocol packages

**HTTP endpoints:**
```
GET /api/v1/trust/health                          -> liveness (no auth)
GET /api/v1/trust/score?agent=ID                  -> lifetime trust score
GET /api/v1/trust/score?session=ID                -> session score + ScoreDelta
GET /api/v1/trust/sessions?active=true&agent=ID   -> list sessions
GET /api/v1/trust/sessions?id=ID                  -> single session detail
GET /api/v1/trust/attestations?agent=ID&since=TS  -> filtered attestations
GET /api/v1/trust/attestations/latest?agent=ID    -> most recent (verified) attestation
```

**Tier gate (locked decision Q3):** Professional+.

**Auth (locked decision Q4):** License key via `pkg/license.LicenseMiddleware`.

### Bug Fixes

- **MEDIUM**: `pkg/trust/score/baseline.go` `(*InMemoryBaseline).GetBaseline` was returning a pointer to a shared struct, causing a data race with concurrent `RecordEvent` callers. Now returns a deep copy. (Phase 8)
- **LOW**: `pkg/compliance/atlas_coverage_test.go` `TestAtlas_Check_Timing` flake (5s limit was tight on busy CI runners). Bumped to 10s with a comment. (Phase 8)

### Tooling

- Go 1.26.3 → 1.26.5 (security fix for `crypto/x509` and `net/textproto` stdlib vulnerabilities). All GPG-signed commits.
- `aegisgate-platform` binary is no longer tracked in git. Build from source: `go build -o aegisgate-platform ./cmd/aegisgate-platform/`. (Phase 7)
- GPG signing configured for all commits. All v3.2.0 commits show `verified: true, reason: valid` on github.com.

### Test Coverage

- `pkg/tier`: 100.0% (was 91.2% pre-v3.1.1; +8.8pp from the Starter tier addition and 6 module constants)
- `pkg/license`: 97.8% (added Modules field, HasModule, Modules, IsValidModule)
- `pkg/compliance`: 95.3% (added gating.go with IsFrameworkEnforced, EvaluateGating)
- `pkg/billing/webhook`: 93.8% (up from 61.9% pre-Phase 1.3; module parsing for 3 input shapes)
- `pkg/trust`: 90.4% (new: session.go, api.go, hooks.go — 60+ new tests)
- Overall: 93.7% (preserved at the v3.1.1 level)

### Files Changed

10 new files, 7 modified, 1 doc-only. See commit history for the per-commit breakdown.

### v2.x Status

**v2.x is end-of-life as of 2026-12-31.** No security updates will be issued after that date. v3.x is the only actively supported line.

### Out of Scope (Deferred)

- **Pro tier price change** — $249 → $499/mo; grandfathered for existing customers (Phase 2)
- **Website updates for 6-pillar hero** (Phase 5)
- **External pentest** — vendor selection open (H4)
- **Legal review** — ToS, Privacy, DPA (H1)

---

## [3.1.1] - 2026-06-05 - Tier Rate Limit Drift Fix

### Summary
Resolves critical drift between website-promised tier limits and code-enforced
tier limits. Adds a first-class Starter tier. Removes the `starter_mode` feature
flag that was masking the gap with a 50% underdelivery. Adds tier validation
in the Stripe webhook handler to prevent unknown tier values from reaching
license generation.

### Bug Fixes
- **CRITICAL**: Starter tier now modeled as a first-class tier in `pkg/tier/tier.go` (was missing; faked via `starter_mode` flag with 50% underdelivery vs. website)
- **CRITICAL**: Developer tier rate limits corrected from 600/300 to 1000/500 RPM (proxy/MCP) to match website
- **CRITICAL**: Professional tier rate limits corrected from 3000/1500 to 10000/5000 RPM to match website
- **CRITICAL**: Developer tier MaxUsers corrected from 10 to 25
- **CRITICAL**: Professional tier MaxUsers corrected from 50 to 100
- **HIGH**: Developer tier MaxAgents corrected from 5 to 25 (per generosity principle)
- **HIGH**: Professional tier MaxAgents corrected from 25 to 100
- **MEDIUM**: `pkg/billing/webhook/server.go` now validates tier via `tier.ParseTier` before license generation; rejects unknown values with `invalid_tier` structured error

### Removed
- `starter_mode` feature flag from `pkg/mcpserver/guardrails.go` (no longer needed; Starter is a real tier)

### Test Coverage
- New `TestStarterTierString`, extended `TestCanAccess` with Starter cases, added `TestStarterMaxConcurrentMCP` in `pkg/tier/tier_test.go`
- New `TestHandleCheckoutCompleted_RejectsInvalidTier`, `TestHandleCheckoutCompleted_AcceptsValidTiers`, `TestHandleCheckoutCompleted_NormalizesAliases`, `TestInferTierFromAmount_AllTiers`, `TestHandleCheckoutCompleted_DefaultsToDeveloperOnUnknownAmount` in `pkg/billing/webhook/tier_validation_test.go`
- Removed `TestStarterModeFeature` and `TestStarterTier_FeatureFlag` from `pkg/mcpserver/`
- Updated `TestHasFeatureHelper` to use placeholder feature name (`beta_features`)

### Out of Scope (Deferred to v3.1.2)
- HIPAA module extraction
- Pro tier price change ($249 → $499)
- Module-level pricing and gating
- Pro tier rate limit upgrade for existing customers (no existing customers; auto-applied at first renewal)

## [2.0.1] - 2026-05-06 - Fail-Closed Security Hardening + SLA/SLO

### Summary
Critical security hardening: fail-closed defaults across all security packages, A2A capability persistence, comprehensive health checks, and SLA/SLO definitions.

### Security Fixes (Fail-Closed Audit)
- **CRITICAL**: A2A capability enforcement now blocks requests with missing capability headers (was silent pass-through)
- **CRITICAL**: MCP guardrails deny untracked sessions, nil tool authorization, and nil STDIO validation (was pass-through)
- **CRITICAL**: Signature verification returns `Valid=false` when disabled (was `Valid=true`)
- **CRITICAL**: MCP verifier denies unsigned initialization requests in all modes (was allowed in non-strict)
- **CRITICAL**: RBAC middleware returns 403 for missing/invalid session IDs (was pass-through)
- **HIGH**: Auth middleware production environment ignores `REQUIRE_AUTH=false` flag (was global bypass)
- **HIGH**: License middleware returns 403 for invalid license keys (was silent Community downgrade)
- **HIGH**: Compliance framework checks return error for unregistered frameworks (was silent pass)
- **HIGH**: MCP `CloseSession` now calls `OnSessionDestroy` to prevent activeSessions counter drift
- **HIGH**: A2A middleware adds panic recovery, structured error codes (14 A2A_ERR_* codes)
- **MEDIUM**: `gosec` alerts resolved — G301 (directory perms), G306 (file perms), G104 (error handling)

### Features
- A2A capability persistence — `PersistentCapEnforcer` saves capabilities to JSON with atomic writes, survives pod restarts
- Comprehensive health checks — `/health` endpoints verify proxy, persistence, license, and certificate subsystems
- SLA/SLO definitions — new `pkg/sla/` package with per-tier SLA commitments and measurable SLOs
- `/api/v1/sla` endpoint — returns SLA details and SLOs for current tier
- Testlab directory removed from git tracking (security: contained credentials and binary)

### Infrastructure
- A2A middleware wired to production router with license-aware enforcement
- A2A configuration added to platform config with environment variable overrides
- `PersistentCapEnforcer` seeds from YAML on first load, persists to JSON on changes

---

## [2.0.0] - 2026-05-05 - A2A Agent Security

### Summary
Major release: Agent-to-Agent (A2A) security guardrails joining HTTP API and MCP protocol protection as the third pillar.

### A2A Security Features
- A2A mTLS authentication — mutual TLS for agent-to-agent communication
- A2A HMAC-SHA256 integrity verification — message authentication codes for request integrity
- A2A per-agent capability enforcement — fine-grained authorization for agent actions
- A2A per-agent token bucket rate limiting — configurable rate limits per agent identity
- A2A license-aware enforcement — tier-based feature gating for A2A capabilities
- A2A → MITRE ATLAS threat mappings — mapping A2A attack patterns to known threat frameworks
- A2A Prometheus metrics — license failures, capability denials, auth failures, integrity failures

### Infrastructure
- `pkg/a2a/` — A2A security middleware with fail-closed defaults
- `configs/a2a.yaml` — HMAC shared secret and rate limit configuration
- `configs/a2a_caps.yaml` — Agent capability map configuration
- CI/CD pipeline updates for A2A integration tests
- Docker release with A2A support

---

## [1.3.8] - 2026-05-02 - Security Headers + DAST Pipeline

### Summary
Security hardening sprint: HTTP security headers, comprehensive CI/CD security pipeline with DAST, pentest simulations, and fuzzing.

### Security Enhancements
- S8-01: HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- S8-02: `pkg/security/headers.go` with tested middleware (94.4% coverage)
- S8-03: Headers applied to proxy (8080) and dashboard (8443) endpoints

### New CI/CD Workflows
- S8-10: `security-comprehensive.yml` - Weekly DAST and pentest pipeline
  - OWASP ZAP API + baseline scan
  - Nmap service discovery
  - Nikto web server scan
  - License bypass pentest simulation
  - RBAC escalation pentest simulation
  - Fuzzing (license, config, scanner parsers)
- S8-11: `docker-compose.test.yml` - CI test environment
- S8-12: `.golangci.yml` - golangci-lint configuration

### Code Quality
- S8-20: golangci-lint integration in CI pipeline
- S8-21: Fix all errcheck violations (middleware, scanners, SSO)
- S8-22: Coverage maintained at 86.7% (above 80% gate)
- S8-23: Coverage exclusion for billing/email/stores (require external services)

### Fuzzing
- S8-30: `pkg/license/license_fuzz_test.go` - License parser fuzzing
- S8-31: `pkg/scanner/scanner_fuzz_test.go` - Scanner fuzzing
- S8-32: `pkg/config_fuzz_test.go` - Config parser fuzzing

## [1.3.7] - 2026-04-27 - SSO Integration + Coverage Boost

### Summary
Sprint 4 complete: OIDC/SAML SSO ported and integrated. 28/29 packages now exceed 80% coverage threshold.

### SSO Integration (Sprint 4)
- S4-01: Ported SSO package from AegisGate upstream (~3,635 LOC)
- S4-02: OIDC provider with PKCE support
- S4-03: SAML 2.0 provider with XML signature validation
- S4-04: SSO middleware wired into auth layer
- S4-05: `/auth/login`, `/auth/callback`, `/auth/logout` endpoints
- S4-06: SSO configuration file (`configs/sso.yaml.example`)
- S4-07: Test lab environment with Keycloak
- S4-08: Mock servers for OIDC and SAML testing

### Test Lab Environment
- Keycloak for real OIDC/SAML testing
- PostgreSQL and Redis for test infrastructure
- Integration tests with `go test -tags=lab`
- Reusable across entire AegisGate project

### Coverage Improvements
- **signature_verification:** 58.6% → **81.8%** (+23.2%)
- **compliance/premium/soc2:** 32.0% → **100%** (+68%)
- **compliance/enterprise/iso42001:** 72.0% → **100%** (+28%)
- **compliance (root):** 49.4% → **58.6%** (+9.2%)

### Changed
- All 28/29 packages pass 80% coverage threshold
- Version bumped to 1.3.7
- SSO endpoints available at `/auth/*`

### Fixed
- Multiple test file syntax errors corrected
- API signature mismatches resolved
- Import cycles broken (auth → sso → auth)

### Documentation
- New `testlab/README.md` for lab environment
- New `plans/sprint4-status.md` for sprint details
- Operations Order updated with Sprint 4 completion


## [1.3.6] - 2026-04-24 - Coverage 86.4%
- CI: Coverage threshold now 80% (was 75%)
- CI: Compliance package excluded from coverage (newly ported, 3K+ lines)
- CI: Fixed coverage calculation to exclude all compliance subdirectories
- signature_verification: 60% coverage, 15 test functions
- compliance: 49% coverage (will improve in v1.3.7+)
- All 25 packages pass tests
- Sprint 3b complete: All tasks marked done

### CI/Fixes
- CI: Coverage threshold 75% (80% for v1.3.6+)
- CI: Tests exclude upstream packages from coverage calculation

### Compliance (Sprint 3 Completion)
- S3-01: Ported Compliance Factory from AegisGuard (1,375 LOC)
- S3-02: Ported Compliance Registry with framework registration/lookup
- S3-03: MITRE ATLAS checks wired (Community-tier mandated)
- S3-04: NIST AI RMF 1.0 checks wired (Community-tier mandated)
- S3-05: OWASP LLM Top 10 checks wired (Community-tier)
- S3-06: ISO 27001 checks wired (Developer+ tier)
- S3-07: GDPR Basic checks wired (Developer+ tier)
- S3-08: HIPAA checks wired (Professional+ tier)
- S3-09: PCI-DSS checks wired (Professional+ tier)
- S3-10: SOC2 Type I checks wired (Professional+ tier)
- S3-11: ISO 42001 checks wired (Enterprise tier)
- S3-12: GDPR Advanced checks wired (Professional+ tier)
- S3-13: Compliance scan endpoint ready via `MCPTierAwareCompliance`
- S3-14: Compliance integration tests written

### Security (Sprint 3b Completion — Continued)
- S3b-03: Signature Verification at MCP Registration complete (pkg/signature_verification)

### Changed
- New `pkg/compliance/mcp_compliance.go` adapter for tier-aware compliance
- 14 MCP compliance tests passing
- All 27 packages passing tests

## [1.3.4] - 2026-04-24

### Security (Sprint 3b Completion)
- S3b-01: STDIO command validation with shell metacharacter injection protection (Guard 6)
- S3b-02: MCP server registration gating with client IP logging
- S3b-04: Authentication enabled by default (REQUIRE_AUTH=false to opt out)
- S3b-05: Hard-enforced memory limits for Community tier sessions
- S3b-07: Tool call limit enforcement (20 tools/session max for Community tier)
- S3b-08: Tool authorization with risk matrix (low/medium/high/critical)
- 18 new STDIO validation tests with comprehensive coverage

### Changed
- Package coverage improved to 84.6% overall (exceeds 80% threshold)
- Go version: 1.25.9

## [1.3.3] - 2026-04-21

### Code Coverage Achievement — Phase 1 Complete

#### 🎯 87.7% Code Coverage (Exceeds 80% Threshold)
- **Scanner Package**: 80.8% coverage (meets 80% target)
- **MCP Server Package**: 81.1% coverage (exceeds 80% target)
- **Overall Platform**: 87.7% coverage (exceeds 80% target)
- **Total Coverage Improvement**: +7.7% from v1.3.2

#### Coverage Test Files Added
- `pkg/scanner/aegisguard_mcp_coverage_test.go` — Comprehensive MCP scanner tests
- `pkg/mcpserver/tools_coverage_test.go` — Tool registration coverage tests

#### Key Fixes and Improvements
- **JSON ID Type Mismatch**: Fixed float64/int comparison in `validateResponse()` for proper JSON-RPC ID validation
- **Concurrent Registration Race**: Added `sync.WaitGroup` for goroutine synchronization
- **Tools Registry Types**: Corrected type imports from `MCPHandler` to `mcp.RequestHandler`
- **Coverage Threshold**: Updated CI workflow to enforce 80% coverage minimum

#### Test Suite Results
- **All Tests Pass**: ✅ 2,348 PASS, 1 SKIP, 0 FAIL
- **Race Detection**: ✅ 0 race conditions detected
- **Test Duration**: 1.2s with race detection enabled
- **Coverage Validation**: Go's built-in `go tool cover` verified

#### Files Modified
| File | Change |
|------|--------|
| `pkg/scanner/aegisguard_mcp.go` | Fixed `validateResponse()` JSON ID comparison logic |
| `.github/workflows/ci.yml` | Coverage threshold updated to 80% |
| `pkg/scanner/aegisguard_mcp_coverage_test.go` | Created comprehensive coverage tests |
| `pkg/mcpserver/tools_coverage_test.go` | Created tool registration coverage tests |

### Code Quality — Production Ready
- **Coverage Distribution**: All packages meeting or exceeding 80% threshold
- **Critical Paths Covered**: All security scanning functions at 80%+
- **Test Reliability**: Zero flaky tests with proper synchronization

---

# Changelog

## [1.3.2] - 2026-04-20

### Legal & IP Protection
- Added `NOTICE` file with trademark reservation and commercial licensing notice
- Added `TRADEMARKS.md` with trademark usage policy
- Standardized entity name to "AegisGate Security, LLC" across all files
- Removed "All rights reserved" from README footer (contradicts Apache 2.0)
- Fixed fabricated 3rd-party copyright in `certificate_test.go`
- Clarified dual-license model: Community = Apache 2.0, Commercial = separate license
- Added `DCO.md` — Developer Certificate of Origin based on Linux kernel DCO 1.1
- Added CI enforcement: DCO check job in CI workflow (strict for PRs, advisory for pushes)
- Updated CONTRIBUTING.md with DCO sign-off instructions and CI enforcement notice
- Fixed stale `aegisgate/` org URLs in CONTRIBUTING.md

### Security Audit — Public Repository Cleanup

#### Files Removed from Repository
- `CI_DEBT.md` — Internal CI debt tracker with commit hashes and lowered quality gates
- `CONSOLIDATION-STATUS.md` — Internal project management with upstream source paths
- `EOF` — Empty junk file
- `MCP_E2E_PREP.md` — Internal E2E test preparation with port configs
- `fix_illegal_runes.sh` — One-shot script with developer username and absolute paths
- `aegisgate-platform.yaml` — Root-level operational config with ML thresholds and Enterprise feature gates
- `ui/frontend/consolidated-dashboard.html` — Internal demo with hardcoded admin/admin credentials and explicit tier pricing

#### .gitignore Hardened
- Added all removed files as gitignore patterns to prevent re-introduction
- Added `docker-compose.override.yml`, `*.tfstate`, `*.tfvars`, `*.kubeconfig`
- Organized into clear sections: Internal Artifacts, Coverage, Binaries, Infrastructure

#### Proprietary Headers Removed (156 files)
- All `PROPRIETARY - AegisGate Security` + trade secret headers removed from Go source
- Resolves legal contradiction with Apache-2.0 open-source license

#### Pricing / Commercial Details Sanitized
- `pkg/tier/tier.go` — Removed `$29/mo`, `$79/mo`, `Custom pricing` comments
- `upstream/aegisgate/pkg/core/tier_features.go` — Removed `GetPriceInfo()`, `GeneratePricingReport()`, vendor-specific tier integrations
- `upstream/aegisgate/pkg/compliance/tier-manager.go` — Removed `PricingInfo` struct, pricing report functions
- `configs/community.yaml` — Removed specific RPM limits, retention periods, paid-tier file references
- `configs/developer.yaml` — Removed feature-differentiation comments and tier rate limits
- `PERFORMANCE.md` — Replaced competitor names with generic labels, removed pricing indicators
- `README.md` — Removed tier-gating indicators from compliance table, removed IP contribution clauses

#### Security Vulnerabilities Fixed
- `docker-compose.yml` — Removed `admin` as default Grafana password; now requires `GRAFANA_PASSWORD` env var
- `upstream/aegisguard/pkg/config/config_defaults.go` — Removed hardcoded JWT secret default (`aegisguard-default-secret-change-me` → empty string)
- `upstream/aegisguard/pkg/license/license.go` — Replaced `admin.aegisgatesecurity.io` with `license.aegisgatesecurity.io`
- `upstream/aegisgate/pkg/core/license_integration_test.go` — Removed `licenseToSign()` function exposing signing format

#### Stale Versions Updated
- `ui/frontend/policy.html` — `v0.2.0` → `v1.3.2`
- `ui/frontend/index_accessible.html` — `v0.15.1` → `v1.3.2`

#### Post-Audit Fixes
- Version badge and all references bumped from v1.3.1 → v1.3.2 (21 files)
- Docs link updated: `docs.aegisgatesecurity.io` → GitHub `docs/` folder (README.md, website)
- `VERSION` file updated to `1.3.2`

---

## [1.3.1] - 2026-04-19

### Phase D Complete: CI/CD Hardening & Security Fixes

#### CI/CD Fixes — All Workflows Now Green
- **pkg/tls module resolution**: Fixed `.gitignore` patterns (`tls/`, `certs/`) that excluded `upstream/aegisgate/pkg/tls/` source from git tracking; added negation rules to restore files
- **Empty package fix**: Created `pkg/tls/certs/doc.go` stub to resolve "invalid package name: ''" error from empty directory
- **gofmt illegal rune literals**: Fixed single-quoted JSON strings in `integration_test.go` (changed to backtick raw strings)
- **TruffleHog scan modes**: Split by event type — PR diff, push filesystem, schedule full history — eliminating "BASE and HEAD are the same" error
- **Trivy SARIF resilience**: Added existence check before SARIF upload step
- **gofmt whitespace**: Fixed formatting issues in 3 test files

#### Security Vulnerability Fixes
- **Go 1.25.8 → 1.25.9**: Resolves 4 stdlib vulnerabilities (GO-2025-3676, GO-2025-3677, GO-2025-3678, GO-2025-3679)
- **gRPC v1.68.0 → v1.79.3**: Resolves GO-2025-3547 (ReDoS in gRPC compression)
- **JWT v5.2.0 → v5.2.2**: Resolves GO-2025-3553 (timing side-channel in HMAC comparison)
- **Result**: 0 known vulnerabilities across all modules (govulncheck verified)

#### Docker / GHCR Publishing
- **Docker image**: Corrected to `ghcr.io/aegisgatesecurity/aegisgate-platform:latest` (v1.3.4)
- **Dockerfile**: Updated base image to `golang:1.25.9-alpine`
- **Image size**: 19.1MB (unchanged)

#### Community & Branding
- **Contact**: Replaced Discord with X/Twitter — [@aegisgatesec](https://x.com/aegisgatesec)
- **Footer**: Heart emoji changed from red (❤️) to black (🖤)

#### CI Results (commit 1065180)
| Workflow  | Status | Details |
|----------|--------|---------|
| CI       | ✅ PASS | 79.9% coverage, 0 vulns, Docker push to GHCR |
| Security | ✅ PASS | govulncheck, gosec, trivy, trufflehog, SBOM, standard-tools |

#### Files Changed
| File | Change |
|------|--------|
| `.gitignore` | Added negation rules for `pkg/tls/` and `pkg/tls/certs/` |
| `.github/workflows/ci.yml` | Go 1.25.9, improved govulncheck |
| `.github/workflows/security.yml` | Go 1.25.9, TruffleHog event split, Trivy check |
| `Dockerfile` | `golang:1.25.9-alpine` |
| `go.mod` (root + upstream + resilience modules) | Go 1.25.9 |
| `upstream/aegisgate/go.mod` | gRPC v1.79.3 |
| `upstream/aegisgate/pkg/tls/certs/doc.go` | New stub package file |
| `upstream/aegisgate/pkg/security/integration_test.go` | Fixed rune literals |
| `README.md`, `docs/website/index.html` | Mastodon, 🖤 |
| All deployment/UI files | Version bumped to v1.3.2 |

---

## [1.3.0] - 2026-04-18

### Phase C Complete: Rate Limiting, Metrics, Deployment

#### C1 — Proxy Rate Limit Callback Pattern
- Added `OnRateLimited func(client string)` callback to proxy
- Wired in main.go: `proxy.OnRateLimited = metrics.RecordRateLimitHit`
- Avoids circular dependency; proxy doesn't import metrics package

#### C2-C5 — Metrics & UI Alignment
- All UI version strings aligned to v1.3.0:
  - `ui/frontend/index.html`
  - `ui/frontend/certificates.html`
  - `ui/frontend/settings.html`
  - `ui/frontend/js/dashboard.js`
- Cleaned 23 coverage files from repository
- Added `*.out` to `.gitignore`
- Complete rewrite of `docs/METRICS.md` documenting all 10 canonical Prometheus metrics

#### C6-C8 — Deployment Artifacts
- **Docker Compose**: Full rewrite with profiles
  - Core: `docker compose up`
  - With Redis: `--profile redis`
  - With Monitoring: `--profile monitoring`
- **Helm Chart** (`deploy/helm/aegisgate-platform/`):
  - Chart.yaml, values.yaml
  - 8 templates: deployment, service, ingress, servicemonitor, pvc, hpa, sa
- **Kubernetes Manifests** (`deploy/k8s/manifests/`):
  - 00-namespace.yaml
  - 01-serviceaccount.yaml
  - 02-pvc.yaml
  - 03-deployment.yaml
  - 04-service.yaml
  - 05-hpa.yaml
  - 06-networkpolicy.yaml
- **Documentation**: `deploy/README.md`

#### C9-C10 — Integration Tests
- `tests/integration/metrics_scrape_test.go` (5 tests):
  - Without service discovery
  - With custom registry
  - When metrics registered
  - Endpoint discovery
  - Empty registry handling
- `tests/integration/ratelimit_counter_test.go` (9 tests):
  - Empty buckets
  - Basic counting
  - Tier limit enforcement
  - Failure scenarios
  - Concurrent clients
  - Bucket expiration
  - Tier changes
  - ExpireRateLimitBuckets helper
  - Per-client isolation

#### Guardrails Enhancement
- **Guard 5**: Per-client RPM rate limiting added to MCP server
- Token bucket implementation with 60s sliding windows
- `SanitizeClientID()` for cardinality control (IPv4→/16)
- `ExpireRateLimitBuckets()` exported test helper
- `ErrRateLimitExceeded` error type

#### Metrics (10 Canonical)
| Metric | Type | Description |
|--------|------|-------------|
| http_requests_total | Counter | HTTP requests by status code and endpoint |
| http_request_duration_seconds | Histogram | Request latency distribution |
| active_connections | Gauge | Current connection count |
| rate_limit_hits_total | Counter | Rate limit violations |
| security_scans_total | Counter | Security scan results |
| mcp_connections | Gauge | Active MCP sessions |
| mcp_requests_total | Summary | MCP request statistics |
| tier_requests_total | Histogram | Requests by tier and endpoint |
| audit_events_total | Summary | Audit log buffer |
| build_info | Gauge | Version metadata |

#### Dependencies
- `github.com/prometheus/client_golang v1.19.0`
- `github.com/prometheus/client_model v0.6.1`

#### Tests
- **Unit Tests**: 320 across 7 packages
- **Integration Tests**: 74 across 3 files
- **E2E Tests**: 7
- **Total Platform Tests**: 401

---

## [1.2.0] - Previous Release
- Initial consolidated platform
- HTTP proxy with MITM scanning
- MCP server with basic guardrails (Guards 1-4)
- Web dashboard
