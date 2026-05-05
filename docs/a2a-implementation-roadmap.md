# A2A Implementation Roadmap & Test Plan

**Sprint 7 – Phase 1 – Deliverable P1‑6**

## Overview
This document outlines the concrete implementation schedule and test strategy for the A2A Protocol Security module. It builds on the **Technical Control Requirements** (`docs/a2a-guardrails-technical-spec.md`) and the **Middleware Architecture** (`docs/a2a-security-middleware-design.md`). The goal is to have a production‑ready A2A guardrail stack integrated into the AegisGate platform by the end of Sprint 7 (7 weeks).

---

## 1️⃣ Weekly Milestones
| Week | Focus Area | Deliverables | Owner |
|------|------------|--------------|-------|
| **Week 1** (2026‑05‑05 – 05‑11) | **Foundation & Skeleton** | - `pkg/a2a` package created (middleware stub) <br> - Secret configuration (`config/a2a.yaml`) <br> - Unit‑test scaffold | 🛠️ Dev Lead |
| **Week 2** (2026‑05‑12 – 05‑18) | **Guardrail G1 & G2** (Auth + Message Integrity) | - `AuthProvider` (mTLS) implementation <br> - HMAC/Ed25519 signature verification <br> - Integration tests for auth + integrity <br> - CI coverage ≥ 80 % for auth & integrity | 🔐 Security Engineer |
| **Week 3** (2026‑05‑19 – 05‑25) | **Guardrail G3 & G6** (Capability & Task ACL) | - In‑memory capability registry <br> - Task ACL middleware <br> - Unit tests for capability enforcement <br> - End‑to‑end test exercising protected task endpoint | 🛡️ Backend Engineer |
| **Week 4** (2026‑05‑26 – 06‑01) | **Guardrail G4 & G5** (Input Validation & Rate Limiting) | - JSON‑schema validation for all A2A messages <br> - Token‑bucket rate limiter <br> - Load‑testing to tune limits <br> - Integration tests for validation & rate‑limit | ⚡ Performance Engineer |
| **Week 5** (2026‑06‑02 – 06‑08) | **Guardrail G7 & G9** (Output Filtering & Notification Verification) | - Output sanitizer (PII/redaction) <br> - HMAC verification for push notifications <br> - Unit & e2e tests for output & notifications | 📡 Ops Engineer |
| **Week 6** (2026‑06‑09 – 06‑15) | **Guardrail G8 & G10** (Agent Registry & Artifact Validation) | - Central agent registry (in‑memory, later DB) <br> - SHA‑256 checksum & optional ClamAV scan <br> - Test suite for artifact handling | 🗂️ Data Engineer |
| **Week 7** (2026‑06‑16 – 06‑22) | **Polish, Docs, Release** | - Full integration test suite (coverage ≥ 90 %) <br> - Update `README.md` with A2A module links <br> - Generate GoDoc for `pkg/a2a` <br> - Tag release `v1.3.9‑a2a` <br> - Deploy to staging environment for manual QA | 🚀 Team Lead |

---

## 2️⃣ Test Plan Overview
| Test Type | Scope | Tools | Success Criteria |
|-----------|-------|-------|------------------|
| **Unit Tests** | Individual guardrail functions (auth, integrity, rate‑limit, etc.) | `testing`, `testify` | ≥ 80 % line coverage per guardrail |
| **Integration Tests** | Middleware chain with mock downstream handler | `net/http/httptest` | All guardrails reject malformed/unauthenticated requests; valid request passes |
| **End‑to‑End Tests** | Full A2A server + client (`adk-go` demo) | Docker Compose, `go test -run TestE2E` | End‑to‑end handshake succeeds, guardrails enforce policies |
| **Load Tests** | Rate limiting & performance under burst traffic | `hey` or `k6` script | ≤ 100 ms latency under 500 RPS, no request queue overflows |
| **Security Scans** | Fuzzing of JSON payloads, signature tampering | `go-fuzz`, `semgrep` | No crashes, all invalid inputs rejected |

---

## 3️⃣ Configuration (`config/a2a.yaml`)
```yaml
# A2A security module configuration
auth:
  ca_path: "certs/ca.pem"
  require_client_cert: true
integrity:
  secret: "{{ env.A2A_HMAC_SECRET }}"
rate_limit:
  burst: 100
  refill_per_minute: 10
capabilities:
  default: []
output_filter:
  redaction_patterns:
    - "(?i)password=.*"
    - "(?i)api_key=.*"
artifact:
  max_size_mb: 10
```
All values are overridable via environment variables for CI/CD pipelines.

---

## 4️⃣ CI/CD Integration
- **GitHub Actions** workflow `a2a.yml` runs `go test ./...` with coverage thresholds.
- **Static analysis** (`golangci-lint`) checks for dead code and potential security issues.
- **Docker image** `ghcr.io/aegisgatesecurity/aegisgate-a2a:latest` built on merge to `main`.
- **Release tag** automatically created when `main` passes all checks.

---

## 5️⃣ Open Tasks & Risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| **Certificate Management** – missing client certs in CI | Build succeeds but runtime auth fails | Use self‑signed dev certs; add CI step to generate them |
| **Rate‑limit Calibration** – overly aggressive limits could break legitimate agents | Service disruption | Load‑test with realistic agent traffic; make limits configurable |
| **Artifact Scan Performance** – ClamAV integration may add latency | Slow responses | Make scanning optional; run async for large artifacts |
| **Documentation Drift** – docs not matching code | User confusion | Generate GoDoc automatically; include doc generation step in CI |

---

## 6️⃣ Acceptance Criteria (Definition of Done)
- All ten guardrails implemented and covered by automated tests.
- `go test ./...` passes with overall coverage ≥ 90 %.
- `README.md` includes a **A2A Security Module** section with links to the three new docs.
- Docker image builds and runs the A2A server with a demo client (`adk-go`) without errors.
- Security audit (static analysis + secret scan) reports no new issues.

---

*Document generated on $(date)*
