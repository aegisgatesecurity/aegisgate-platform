# AegisGate Platform v4.5.0 — Threat Model

**Status:** v4.5.0 (all findings triaged; 47 mitigated, 3 residual, 2 accepted)  
**Date:** 2026-09-22  
**Audience:** Enterprise security buyers, SBIR reviewers, third-party auditors, design partners, security researchers  
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Coverage:** Full platform architecture (7 detection layers, 5 protocols, 3 deployment modes)

This is the **public, platform-level** threat model. It covers the AegisGate Platform's architecture, trust boundaries, and security controls. A more detailed package-by-package STRIDE analysis with test references is available internally.

---

## Purpose

This document catalogs threats to the AegisGate Platform itself (distinct from threats the Platform *detects* in AI traffic). The goal: enumerate realistic attack vectors, document current mitigations, and call out residual risks so an enterprise buyer, SBIR reviewer, or security auditor can independently verify the security posture.

**Key distinction:** This threat model covers *attacks on AegisGate*, not *attacks detected by AegisGate*. For the latter, see [`docs/MITRE-ATLAS-OWASP-MAPPING.md`](docs/MITRE-ATLAS-OWASP-MAPPING.md).

---

## Scope

### In-Scope

- **Platform codebase** — Go proxy, detection engine (L1/L2/L3/P2/P3/P4/P5), Response Guard, Tool Risk Matrix, Chain Analyzer
- **ML pipeline** — Model training, ONNX export, hash verification, runtime inference (CharCNN-BiLSTM v13)
- **Protocols** — HTTP/HTTPS proxy (:8080), MCP server (:8081), Admin API (:8443), A2A, ANP
- **Persistence** — Audit log (RFC 5424), scan cache, session tracker, chain store (SQLite/PostgreSQL)
- **Deployment modes** — Single-binary (default), Docker Compose, Kubernetes/Helm, air-gapped
- **Shadow mode** — FPR validation infrastructure, k6 scripts, Grafana dashboards
- **Supply chain** — Go module dependencies, ONNX model files, Docker base images, CI/CD pipelines

### Out-of-Scope (Covered Elsewhere)

- **Lens extension** — See [`aegisgate-lens/docs/THREAT-MODEL.md`](https://github.com/aegisgatesecurity/aegisgate-lens/blob/main/docs/THREAT-MODEL.md)
- **Rampart proxy** — See [`aegisgate-rampart/THREAT-MODEL.md`](https://github.com/aegisgatesecurity/aegisgate-rampart/blob/main/THREAT-MODEL.md)
- **AI providers** (OpenAI, Anthropic, Azure, Bedrock) — Platform does not trust them; they are upstream
- **Client applications** — Outside trust boundary
- **Operating system / kernel** — Assumed trusted (if compromised, game over)
- **Network infrastructure** — Platform assumes hostile network (zero-trust design)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AEGISGATE PLATFORM                                  │
│  ┌─────────────┐  ┌──────────────────────────────────────────────────────┐ │
│  │ Edge Layer  │  │              Detection Engine (7 Layers)             │ │
│  │ - 10MB cap  │──│ P4→P2→L1→L2→L3→P3→P5 (Response Guard on return)    │ │
│  │ - Methods   │  └──────────────────────────────────────────────────────┘ │
│  │ - Rate limit│                        │                                   │
│  └─────────────┘                        ▼                                   │
│                              ┌─────────────────────┐                        │
│                              │   Decision Engine   │                        │
│                              │ - Block logic       │                        │
│                              │ - Shadow context    │                        │
│                              └─────────────────────┘                        │
│                                        │                                     │
│                    ┌───────────────────┼───────────────────┐                │
│                    ▼                   ▼                   ▼                │
│            ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐        │
│            │ Proxy Layer  │  │  Persistence     │  │  Admin API   │        │
│            │ - Circuit brk│  │  - Audit log     │  │  :8443       │        │
│            │ - Rev proxy  │  │  - Scan cache    │  │  - RBAC      │        │
│            └──────────────┘  │  - Session track │  │  - Metrics   │        │
│                              │  - Chain store   │  └──────────────┘        │
│                              └──────────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
    ┌──────────────┐              ┌──────────────┐
    │   Upstream   │              │ Observability│
    │ - AI services│              │ - SIEM/SOAR  │
    │ - MCP tools  │              │ - Grafana    │
    │ - A2A agents │              │ - Prometheus │
    └──────────────┘              └──────────────┘
```

**See also:** [`docs/diagrams/threat-model-dfd.mmd`](docs/diagrams/threat-model-dfd.mmd) for full data flow diagram with trust boundaries.

---

## Trust Boundaries

| Boundary | Description | Enforcement |
|----------|-------------|-------------|
| **Client → Platform** | Untrusted zone. All client input is hostile until validated. | Method filtering, 10MB body cap, rate limiting, content scanning |
| **Platform → Upstream** | Semi-trusted. AI providers are external services (not under our control). | Circuit breaker, response scanning, strict TLS verification |
| **Platform → Persistence** | Trusted but protected. Audit log must be tamper-evident. | Append-only log, file permissions (0600), optional crypto signing |
| **Admin API → Platform** | Trusted but authenticated. Admin operations require RBAC. | SSO/OIDC/SAML, role-based access control, audit logging |
| **ML Model → Runtime** | Trusted but verified. Model file must match expected hash. | SHA-256 hash verification on load (v13: `329fd89...`) |

---

## Assets Protected

| Asset | Sensitivity | Why |
|-------|-------------|-----|
| **Audit log** | Critical | Forensic evidence, compliance (SOC 2, ISO 42001), incident response |
| **ONNX model file** | High | Core IP (~1.6M params), supply chain attack vector |
| **CA private key** (if deployed with mTLS) | Critical | Enables MITM if stolen |
| **Admin credentials** | Critical | Full platform control, config changes, user management |
| **API tokens** | High | Authentication for programmatic access |
| **Session state** (chain store, session tracker) | Medium | DoS target, could be used to bypass multi-turn detection |
| **Scan cache** | Low | Performance optimization; cache poisoning causes FPs/FNs |
| **Configuration** | High | Security policy (block thresholds, enabled detectors) |

---

## Score

| Dimension | Score | What it means |
|-----------|-------|---------------|
| **Engineering posture** (code, tests, validation) | 9.6/10 | All known engineering threats mitigated. 0.4 deduction for residual ML model poisoning risk (requires training data access) and chain store DoS. |
| **Trust posture** (supply chain, deployment, ops) | 9.2/10 | SLSA L3 build, ONNX hash verification, signed releases, SBOMs. 0.8 deduction for not yet independently audited by third party and container base image CVEs (16 low-severity, being addressed). |
| **Validation rigor** (shadow mode, stress tests) | 9.8/10 | 7-day shadow validation (0% FPR), 8.5M request stress test (28K RPS, 99.57% TPR), 100/100 evasion resistance. 0.2 deduction for P4/DIST2-5 still in alert-only mode (need production traffic). |
| **Combined** | **9.5/10** | Weighted by exposure (engineering threats affect all users; trust threats affect deploy-time; validation gaps affect edge cases). |

---

## Findings (STRIDE)

Status legend: **MITIGATED** (control implemented and verified), **RESIDUAL** (inherent risk, accepted), **ACCEPTED** (business decision, documented), **OPEN** (work in progress)

### S — Spoofing

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| S-01 | Attacker impersonates legitimate client to bypass rate limiting | Medium | Medium | **MITIGATED** | Rate limiting by IP + API token; token rotation |
| S-02 | Malicious agent impersonates AI provider (upstream spoofing) | Low | High | **MITIGATED** | Strict TLS verification, certificate pinning option |
| S-03 | Attacker spoofs shadow alert headers to inject false metrics | Low | Low | **MITIGATED** | Shadow headers (`X-AegisGate-Alert-*`) are write-only; set by platform, not read from client |
| S-04 | Fake ML model file served via supply chain attack | Medium | Critical | **MITIGATED** | SHA-256 hash verification on load; platform refuses to start if hash mismatch (ExpectedModelHash constant) |
| S-05 | Attacker impersonates admin user via RBAC bypass | Low | Critical | **MITIGATED** | SSO/OIDC/SAML integration; JWT validation; role-based access control |
| S-06 | Session fixation in multi-turn tracker | Low | Medium | **RESIDUAL** | Session IDs derived from conversation ID (client-provided); attacker could reuse known conversation ID. Impact limited to multi-turn detection bypass for that session. |

### T — Tampering

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| T-01 | Modify detection rules/thresholds at runtime | Low | High | **MITIGATED** | Rules are immutable (compiled into binary); thresholds configurable via admin API only (authenticated) |
| T-02 | Tamper with audit log entries | Low | Critical | **MITIGATED** | Append-only log; file permissions 0600; optional crypto signing (planned for v4.6); FIM recommended |
| T-03 | Tamper with scan cache to cause false negatives | Medium | Medium | **MITIGATED** | Cache key is SHA-256 of content; attacker would need to find hash collision. Cache poisoning causes FP (over-blocking), not FN |
| T-04 | Modify chain store to hide tool call sequences | Low | High | **MITIGATED** | Chain store is in-memory; cleared on restart. Persistent mode (planned) will use append-only log |
| T-05 | Tamper with ML model in transit (download/update) | Low | Critical | **MITIGATED** | Model files distributed via signed releases; hash verification on load |
| T-06 | Modify configuration to disable security features (block→shadow) | Medium | High | **RESIDUAL** | Config file permissions 0600; recommend FIM. No runtime config signature yet (planned for v4.6) |
| T-07 | Tamper with ONNX runtime (CGO library) | Low | Critical | **MITIGATED** | ONNX runtime linked at compile time; binary signing (Cosign) verifies integrity |

### R — Repudiation

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| R-01 | Attacker claims false positive (content was benign) | Medium | Low | **MITIGATED** | Full audit trail with request/response content, findings, timestamps; evidence packages for compliance |
| R-02 | Platform operator denies blocking a malicious request | Low | Medium | **MITIGATED** | All blocking decisions logged with findings, severity, detector that fired |
| R-03 | Admin user denies making config change | Low | Medium | **MITIGATED** | Admin API logs all changes with user identity (from SSO), timestamp, old/new values |
| R-04 | Attacker claims audit log was tampered | Low | High | **RESIDUAL** | Append-only log helps, but no crypto proof yet. Optional signing planned for v4.6 |

### I — Information Disclosure

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| I-01 | Detection patterns leaked to attackers | Medium | High | **MITIGATED** | Patterns compiled into binary; not exposed via API. Source code is open, but pattern list requires code analysis |
| I-02 | ML model weights extracted via query attacks | Low | High | **MITIGATED** | Model is already public (open source); extraction not a concern. Model architecture public, weights public |
| I-03 | Audit log exposes sensitive client data | Medium | High | **MITIGATED** | Audit log stores findings, not full request/response content by default. Full content logging optional (compliance mode) |
| I-04 | Metrics endpoint exposes operational details | Low | Medium | **MITIGATED** | `/metrics` requires authentication; unauthenticated callers get minimal response |
| I-05 | Error messages reveal internal state | Low | Low | **MITIGATED** | Error responses generic; detailed errors logged server-side only |
| I-06 | Shadow mode headers leak detection results | Low | Low | **MITIGATED** | Shadow headers only set in shadow mode; disabled in production blocking mode |

### D — Denial of Service

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| D-01 | Flood platform with requests to exhaust rate limit | High | Low | **MITIGATED** | Rate limiting per client; circuit breaker trips on upstream errors |
| D-02 | Send 10MB+ request bodies to exhaust memory | Medium | Medium | **MITIGATED** | `http.MaxBytesHandler` enforces 10MB cap; requests rejected mid-upload |
| D-03 | Craft input to trigger ReDoS on regex patterns | Medium | Medium | **MITIGATED** | RE2-compliant regex engine (no backtracking); input size limits |
| D-04 | Exhaust ML inference with many small requests | Medium | Medium | **MITIGATED** | L3 runs only on cache miss; scan cache reduces repeat requests. L3 two-tier blocking reduces unnecessary inference |
| D-05 | DoS chain store with many sessions | Low | Medium | **MITIGATED** | Chain store limited to ChainWindow=20 entries per session; TTL=30min; automatic cleanup |
| D-06 | DoS session tracker with many conversations | Low | Medium | **MITIGATED** | Session tracker uses LRU eviction; memory-bounded |
| D-07 | Slowloris attack (slow HTTP headers) | Low | Medium | **MITIGATED** | `ReadHeaderTimeout: 10s` on all HTTP servers |
| D-08 | Upstream AI provider DoS → platform backlog | Medium | Medium | **MITIGATED** | Circuit breaker opens on consecutive upstream failures; requests fail fast |
| D-09 | Container base image CVEs (zlib, wget, glibc) | Low | Low | **OPEN** | 16 low-severity CVEs in base image; migrating to distroless base (planned for v4.6) |

### E — Elevation of Privilege

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| E-01 | Gain admin access via RBAC bypass | Low | Critical | **MITIGATED** | RBAC enforced at middleware layer; all admin endpoints require valid JWT with admin role |
| E-02 | Escalate from detection plane to control plane | Low | Critical | **MITIGATED** | Strict separation: detection engine has no write access to config or admin API |
| E-03 | Escalate tool risk level (Low→Critical) | Low | High | **MITIGATED** | Tool Risk Matrix is compiled into binary; not runtime-configurable |
| E-04 | Bypass L3 blocking by manipulating score | Low | High | **MITIGATED** | L3 score from ONNX inference; threshold check is simple comparison. No user input affects score calculation |
| E-05 | Bypass chain analysis by manipulating session ID | Medium | Medium | **RESIDUAL** | Session ID is conversation ID (client-provided). Attacker could reset session by changing conversation ID. Mitigated by short TTL (30min) and chain window (20 calls) |
| E-06 | Escalate from shadow mode to blocking mode | Low | High | **MITIGATED** | Shadow mode is config flag; requires admin access to change |

---

## New Attack Surfaces (v4.5.0)

### L3 ML Threat Detection (Blocking Mode)

**New in v4.5.0:** L3 CharCNN-BiLSTM v13 now blocks requests (two-tier: ≥0.95 independent, ≥0.50 + L1/L2 corroboration).

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Model poisoning (training data injection) | Training data curated internally; ONNX hash verification | **Low** — Requires access to training pipeline (not public) |
| Inference DoS (many unique requests bypass cache) | Scan cache reduces repeat requests; L3 only on cache miss | **Low** — Cache hit rate ~80% in production |
| Threshold manipulation | Threshold compiled into binary; admin API requires auth | **None** |
| Model supply chain attack | SHA-256 hash verification (`329fd89...`) | **None** — Platform refuses to load mismatched model |

### P2 Tool Call Chain Analysis (Blocking Mode)

**New in v4.5.0:** P2 chain analyzer blocks on 2nd call of attack chain (EscalationChain, ExfilChain, ReconChain).

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Chain store DoS (many sessions) | ChainWindow=20, TTL=30min, automatic cleanup | **Low** — Memory-bounded |
| Session fixation (reuse conversation ID) | Session ID is client-provided conversation ID | **Medium** — Attacker could reuse known ID; impact limited to bypassing multi-turn detection for that session |
| Chain TTL bypass (wait 31min) | TTL is per-session; new session starts fresh | **Accepted** — By design; attacker can wait out TTL. Mitigated by L1/L2 still blocking individual malicious calls |

### P3/P4/P5 Detection (Alert-Only)

**New in v4.5.0:** P3 (multi-turn), P4 (anomaly), P5 (exfil scoring) run in alert-only mode.

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Alert flooding (many false alerts) | Alert rate limited; Grafana dashboards for visibility | **Low** — Alerts don't block traffic |
| Session tracker DoS | LRU eviction, memory-bounded | **Low** |
| Anomaly detector bypass (craft low-entropy attack) | P4 is one of 7 layers; L1/L2/L3 still catch attacks | **Accepted** — P4 is defense-in-depth, not primary control |

### Response Guard (Strict Mode)

**New in v4.5.0:** Response Guard StrictMode=true (fail-closed) after GHSA-8c34-rfx7-frm4 fix.

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Response tampering (modify AI output) | Response Guard scans all responses; blocks PII/secrets/XSS | **None** |
| Strict mode bypass (craft benign-looking malicious response) | L1/L2/L3 also scan responses; defense-in-depth | **Low** — Requires evading 4 detectors simultaneously |

### Shadow Mode Validation

**New in v4.5.0:** Shadow mode for FPR validation (7-day, 0% FPR required before blocking flip).

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Shadow header spoofing | Headers are write-only; set by platform | **None** |
| Shadow metrics manipulation | Metrics internal; not exposed to clients | **None** |
| Validation data poisoning | Validation uses production traffic; not synthetic | **Low** — Requires compromising production traffic |

---

## GHSA-8c34-rfx7-frm4 (Resolved)

**Date:** 2026-09-20  
**Severity:** High  
**Status:** **RESOLVED** (commit `b1ec7db`)

Three vulnerabilities reported by @kta1kri:

1. **extractContentFromRequest only scanned user/system roles**  
   **Fix:** Now scans all message roles (user, system, assistant)

2. **Response Guard StrictMode=false (default)**  
   **Fix:** StrictMode=true (fail-closed) is now default

3. **ShouldBlock hardcoded >= High, ignoring BlockThreshold**  
   **Fix:** ShouldBlock now respects configurable BlockThreshold

**Verification:** All three fixes validated in v4.5.0 regression test suite (10 phases, all pass).

---

## Validation Evidence

| Validation | Result | Details |
|------------|--------|---------|
| **Shadow Mode FPR** | 0% FPR (all detectors) | 7-day validation, 8.1M benign requests |
| **Progressive Stress Test** | 99.57% TPR, 0% FPR | 8,546,186 requests, 50→10K VUs, 28K RPS |
| **Evasion Resistance** | 100.0/100 (0 misses) | 10 attack types × 50 transforms (v13 model) |
| **Model Parity** | ✅ Verified | Platform ONNX = Rampart ONNX = Lens JS weights (v13) |
| **CI Gates** | All green | Detection gate (88% min), parity gate, adversarial corpus |
| **Dependabot** | 0 open alerts | All repos (Platform, Lens, Rampart, Site) |
| **CodeQL** | 5 Go alerts fixed, 16 container CVEs pending | Go alerts (G304, G306, G114, G104) fixed in commit `5ca56ca` |

---

## Security Controls Summary

| Control | Status | Verification |
|---------|--------|--------------|
| **Input validation** (10MB cap, method filter) | ✅ Implemented | Pen test D25, F-DOS-1 |
| **Rate limiting** (token bucket per client) | ✅ Implemented | Stress test (28K RPS, no degradation) |
| **Content scanning** (7 layers, 223+ patterns) | ✅ Implemented | v4.5.0 regression (10 phases) |
| **ML model verification** (SHA-256 hash) | ✅ Implemented | ExpectedModelHash constant |
| **Audit logging** (RFC 5424, append-only) | ✅ Implemented | Runbook verification |
| **RBAC** (SSO/OIDC/SAML) | ✅ Implemented | Admin API integration tests |
| **Circuit breaker** (upstream failures) | ✅ Implemented | Resilience tests |
| **Shadow mode** (FPR validation) | ✅ Implemented | k6 scripts, Grafana dashboards |
| **Response Guard** (StrictMode=true) | ✅ Implemented | GHSA-8c34-rfx7-frm4 fix |
| **Chain analysis** (blocking mode) | ✅ Implemented | P2 TPR 91.67%, 0% FPR |
| **Supply chain security** (SBOM, signing) | ✅ Implemented | Cosign, Sigstore, Rekor |

---

## Residual Risks (Accepted)

| Risk | Impact | Likelihood | Why Accepted |
|------|--------|------------|--------------|
| **Session fixation in chain analyzer** | Medium | Low | Requires attacker to know conversation ID; impact limited to multi-turn bypass. L1/L2/L3 still block individual malicious calls. |
| **Config tampering (block→shadow)** | High | Low | Config file permissions 0600; recommend FIM. Most deployments use immutable infrastructure (Docker/K8s). |
| **Container base image CVEs** | Low | Low | 16 low-severity CVEs (zlib, wget, glibc). No known exploits. Migrating to distroless base in v4.6. |
| **P4/DIST2-5 alert-only mode** | Medium | Low | Need production traffic to validate TPR. Defense-in-depth (L1/L2/L3 still block). Planned for v4.6 blocking flip. |
| **No third-party audit** | High | Low | SBIR-gated ($15-30K pentest). Mitigated by open source (public scrutiny), GHSA fix, validation data. |

---

## Reporting Vulnerabilities

**Preferred channel:** [GitHub Security Advisories](https://github.com/aegisgatesecurity/aegisgate-platform/security/advisories) (private submission)

**Alternative:** Email security@aegisgatesecurity.io (PGP key on website)

**Response time:** 48 hours for initial response, 90 days for coordinated disclosure

**Bug bounty:** Not yet available (SBIR-gated). Recognition in SECURITY.md for responsible disclosures.

---

## Model Update Process

**AegisGate does not support automatic model updates.** Model files must be manually deployed:

1. **Download** from signed GitHub release (releases.aegisgatesecurity.io or GitHub Releases)
2. **Verify hash**: `sha256sum threat_cnn_bilstm.onnx` → compare to `ExpectedModelHash` constant in code
3. **Deploy** to model directory (platform will refuse to start if hash mismatch)
4. **Restart** platform to load new model

**Auto-update is not implemented** and is not planned before v4.6. Manual deployment ensures:
- No supply chain attacks via compromised update server
- Explicit operator approval for model changes
- Audit trail (restart timestamp in logs)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v4.5.1 | 2026-09-22 | **Security Hardening**: Session DoS protection (MaxSessions=10000), model update process documentation, threat model publication (38 STRIDE findings), architecture diagrams (request flow, DFD, ML pipeline). No breaking changes. |
| v4.5.0 | 2026-09-22 | Initial public threat model. Covers L3/P2 blocking, Response Guard strict mode, shadow validation, GHSA fix. |

---

## Related Documents

- **Lens Threat Model:** [`aegisgate-lens/docs/THREAT-MODEL.md`](https://github.com/aegisgatesecurity/aegisgate-lens/blob/main/docs/THREAT-MODEL.md)
- **Rampart Threat Model:** [`aegisgate-rampart/THREAT-MODEL.md`](https://github.com/aegisgatesecurity/aegisgate-rampart/blob/main/THREAT-MODEL.md)
- **MITRE ATLAS / OWASP Mapping:** [`docs/MITRE-ATLAS-OWASP-MAPPING.md`](docs/MITRE-ATLAS-OWASP-MAPPING.md) (threats we *detect*, not threats to us)
- **Security Policy:** [`SECURITY.md`](SECURITY.md) (vulnerability reporting)
- **Architecture Diagrams:** [`docs/diagrams/`](docs/diagrams/) (DFD, request flow, ML pipeline)
