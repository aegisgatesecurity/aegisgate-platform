# Prometheus Metrics Documentation — AegisGate Platform v1.3.1

AegisGate Platform exposes 10 canonical Prometheus metrics with full cardinality
protection for production monitoring, alerting, and capacity planning.

## Endpoint

```
http://localhost:8443/metrics
```

## Canonical Metrics (10 total)

### HTTP Request Metrics

| Metric | Type | Description | Labels | Cardinality |
|--------|------|-------------|--------|-------------|
| `aegisgate_http_requests_total` | Counter | Total HTTP requests processed | method, endpoint, status | High (≤1000 per label) |
| `aegisgate_http_request_duration_seconds` | Histogram | Request latency distribution | method, endpoint | High (≤1000 per label) |

### Connection & Rate Limit Metrics

| Metric | Type | Description | Labels | Cardinality |
|--------|------|-------------|--------|-------------|
| `aegisgate_active_connections` | Gauge | Current active connections by service | service | Low (≤10) |
| `aegisgate_rate_limit_hits_total` | Counter | Rate limit triggers | service, client | High (≤1000 per label) |

### MCP Metrics

| Metric | Type | Description | Labels | Cardinality |
|--------|------|-------------|--------|-------------|
| `aegisgate_mcp_connections` | Gauge | Active MCP sessions | — | Low (1) |
| `aegisgate_mcp_requests_total` | Counter | MCP tool invocations | tool, result | Medium (≤100) |

### Security & Compliance Metrics

| Metric | Type | Description | Labels | Cardinality |
|--------|------|-------------|--------|-------------|
| `aegisgate_security_scans_total` | Counter | Security scan invocations | type, result | Medium (≤100) |
| `aegisgate_audit_events_total` | Counter | Total audit events logged | — | Low (1) |

### Platform Metrics

| Metric | Type | Description | Labels | Cardinality |
|--------|------|-------------|--------|-------------|
| `aegisgate_tier_requests_total` | Counter | Requests by license tier | tier | Low (≤4) |
| `aegisgate_build_info` | Gauge | Build & runtime metadata | version, goversion, platform | Low (≤10) |

---

## Cardinality Control System

All metrics use the cardinality-safe sanitization layer in `pkg/metrics/cardinality.go`
to prevent metrics explosion in production. Every dynamic label value passes through
a sanitizer before reaching Prometheus.

### Cardinality Tiers

| Tier | Limit | Use Case | Examples |
|------|-------|-----------|----------|
| Low | ≤10 | Fixed enumerations | tier names, service components |
| Medium | ≤100 | Bounded domains | HTTP methods, whitelisted tool names |
| High | ≤1000 | Sanitized dynamic values | client IPs (bucketed), endpoints (collapsed) |
| Unbounded | Blocked | Never use | user IDs, session tokens, raw URLs |

### Sanitization Functions

#### `SanitizeEndpoint(path)` — HTTP endpoint collapsing

Transforms high-cardinality URL paths into bounded labels:

| Raw Path | Sanitized | Rule |
|----------|-----------|------|
| `/api/v1/users/123` | `/api/vN/:id` | Numeric ID → `:id` |
| `/api/v1/scans/550e8400-...` | `/api/vN/:uuid` | UUID → `:uuid` |
| `/health/live` | `/health` | Prefix normalization |
| `/metrics/prometheus` | `/metrics` | Prefix normalization |
| `/mcp/tools/invoke` | `/mcp/:operation` | MCP routing collapse |
| `/static/js/app.abc123.js` | `/static/:file` | Static asset collapse |

Two-pass replacement: (1) token patterns (UUIDs, ObjectIDs, numeric IDs) applied
globally, then (2) prefix patterns applied first-match-wins.

#### `SanitizeClientID(client)` — IP address bucketing

Reduces per-client cardinality by masking low-order octets:

| Raw Client | Sanitized | Reason |
|------------|-----------|--------|
| `192.168.1.100:1234` | `192.168.x.x` | IPv4: keep first 2 octets |
| `10.0.0.5:8080` | `10.0.x.x` | IPv4: keep first 2 octets |
| `2001:db8::1` | `2001::/block` | IPv6: keep first segment |
| (empty) | `anonymous` | No client info |

#### `SanitizeToolName(name, allowed)` — MCP tool whitelisting

Unknown tool names are bucketed to `"unknown"` to prevent malicious MCP servers
from causing cardinality explosion via dynamic tool names.

#### `ValidateLabelValue(value, maxLen)` — Safety net

Ensures all label values meet Prometheus naming requirements (alphanumeric,
`_-.:/`) and respects length limits. Overrides unsafe characters with `_`.

### Label Name Constants

All label names are defined as constants in `pkg/metrics/labels.go` to prevent
typos and ensure consistency across metrics:

```go
LabelMethod, LabelEndpoint, LabelStatus   // HTTP
LabelService, LabelClient                   // Connections/rate limits
LabelTool, LabelResult                      // MCP
LabelScanType                               // Security
LabelTier                                    // Platform
LabelVersion, LabelGoVersion, LabelPlatform // Build info
```

### Label Value Constants

Fixed label values are also constants to prevent drift:

```go
ServiceProxy, ServiceMCP, ServiceDashboard, ServicePersistence, ServiceCertificate, ServiceScanner
ResultSuccess, ResultFailure, ResultBlocked, ResultError, ResultTimeout, ResultRateLimited, ResultUnauthorized
ScanVuln, ScanSecret, ScanPII, ScanInjection, ScanCompliance
TierCommunity, TierDeveloper, TierProfessional, TierEnterprise
```

---

## Recording Functions

### `RecordHTTPRequest(method, endpoint, status, duration)`
Records an HTTP request. Endpoint is sanitized via `SanitizeEndpoint()`.
Status is recorded as a class (`"2xx"`, `"4xx"`) via `StatusClass()`.

### `SetActiveConnections(service, count)` / `IncActiveConnections` / `DecActiveConnections`
Track active connections. Service is one of the `Service*` constants.

### `RecordRateLimitHit(service, client)`
Records a rate limit hit. Client is bucketed via `SanitizeClientID()`.
Called from: **proxy** (429 path, via `OnRateLimited` callback) and **MCP guardrails**
(Guard 5: per-client RPM limit).

### `RecordSecurityScan(scanType, result)`
Records a security scan. Use `Scan*` constants for type, `Result*` for result.

### `SetMCPConnections(count)`
Sets the absolute MCP session count gauge.

### `RecordMCPRequest(tool, result)`
Records an MCP tool invocation. Tool names should be sanitized via `SanitizeToolName()`.

### `RecordTierRequest(tier)`
Records a request attributed to a tier. Use `Tier*` constants.

### `RecordAuditEvent()`
Increments the total audit event counter.

### `SetBuildInfo(version, goversion, platform)`
Sets build metadata. Call once at startup.

---

## Integration Architecture

### Proxy → Metrics (Callback Pattern)

The proxy package does **not** import the metrics package directly. Instead:

```go
// cmd/aegisgate-platform/main.go
proxyOpts := &proxy.Options{
    OnRateLimited: func(client string) {
        metrics.RecordRateLimitHit(metrics.ServiceProxy, client)
    },
}
```

This callback pattern avoids circular imports and keeps packages decoupled.

### MCP Guardrails → Metrics (Direct Import)

The MCP guardrail middleware directly imports `pkg/metrics` because
`pkg/mcpserver` → `pkg/metrics` is a clean dependency direction (no cycles).

Guard 5 (rate limiting) calls `RecordRateLimitHit(metrics.ServiceMCP, client)`
on MCP rate limit violations.

### HTTP Middleware → Metrics (WrapHandler)

```go
handler = metrics.WrapHandler("proxy", proxyMux)
```

`WrapHandler` wraps any `http.Handler` with request counting, latency
histograms, and status code tracking using a response-writer wrapper.

---

## Histogram Buckets

### HTTP Request Duration (`DefaultHTTPBuckets`)
```go
{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}
```

### MCP Request Duration (`DefaultMCPBuckets`)
```go
{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0}
```

---

## Example Prometheus Queries

### Request Rate by Service
```promql
sum by (service) (rate(aegisgate_http_requests_total[5m]))
```

### Error Rate (5xx)
```promql
sum(rate(aegisgate_http_requests_total{status=~"5.."}[5m]))
/
sum(rate(aegisgate_http_requests_total[5m]))
```

### P95 Latency
```promql
histogram_quantile(0.95,
  rate(aegisgate_http_request_duration_seconds_bucket[5m]))
```

### Rate Limit Triggers by Service
```promql
sum by (service) (rate(aegisgate_rate_limit_hits_total[5m]))
```

### MCP Tool Usage
```promql
topk(10, sum by (tool) (rate(aegisgate_mcp_requests_total[5m])))
```

### Active MCP Sessions
```promql
aegisgate_mcp_connections
```

### Tier Distribution
```promql
sum by (tier) (rate(aegisgate_tier_requests_total[5m]))
```

---

## Recommended Alerts

```yaml
# High error rate
- alert: HighErrorRate
  expr: |
    sum(rate(aegisgate_http_requests_total{status=~"5.."}[5m]))
    /
    sum(rate(aegisgate_http_requests_total[5m])) > 0.1
  for: 5m
  severity: critical
  labels:
    framework: NIST-AI-RMF

# High latency (P95 > 500ms)
- alert: HighLatency
  expr: |
    histogram_quantile(0.95,
      rate(aegisgate_http_request_duration_seconds_bucket[5m])) > 0.5
  for: 5m
  severity: warning

# Rate limiting triggered (proxy or MCP)
- alert: RateLimitActive
  expr: sum(rate(aegisgate_rate_limit_hits_total[5m])) > 0
  for: 1m
  severity: info
  annotations:
    summary: "Rate limiting is actively blocking requests"
    runbook: "Review client distribution: topk(5, aegisgate_rate_limit_hits_total)"

# MCP session exhaustion
- alert: MCPConnectionSpike
  expr: aegisgate_mcp_connections > 100
  for: 5m
  severity: warning
  annotations:
    summary: "MCP connection count exceeds 100"

# Security scan failures
- alert: SecurityScanFailures
  expr: rate(aegisgate_security_scans_total{result="blocked"}[5m]) > 0
  severity: critical
  labels:
    framework: MITRE-ATLAS

# Build version change (deployment detection)
- alert: DeploymentDetected
  expr: aegisgate_build_info
  for: 0m
  severity: info
  annotations:
    summary: "New deployment detected (check version label)"
```

---

## Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'aegisgate-platform'
    static_configs:
      - targets: ['localhost:8443']
    metrics_path: /metrics
    scrape_interval: 15s
    scrape_timeout: 10s
```

### Pushgateway (optional, for short-lived jobs)

```go
metrics.PushMetrics("pushgateway:9091", "aegisgate")
```

---

## Grafana Dashboard

See `docs/grafana/dashboard.json` for a pre-configured dashboard.

## Registry & Reset

For testing, use `metrics.NewRegistry()` to create an isolated Prometheus
registry. `Registry.Reset()` clears all metrics between test runs.
