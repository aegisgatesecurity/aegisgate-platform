# Changelog

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
- **Docker image**: Successfully published to GHCR as `ghcr.io/aegisgatesecurity/aegisgate-platform/aegisgate:v1.3.1`
- **Dockerfile**: Updated base image to `golang:1.25.9-alpine`
- **Image size**: 19.1MB (unchanged)

#### Community & Branding
- **Contact**: Replaced Discord with Mastodon — [@aegisgatesecurity](https://mastodon.social/@aegisgatesecurity)
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
| `README.md`, `docs/website/index.html` | Mastodon, 🖤, v1.3.1 |
| All deployment/UI files | Version bumped to v1.3.1 |

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
