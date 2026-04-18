# Prometheus Metrics Documentation

AegisGate Platform exposes comprehensive Prometheus metrics for production monitoring and alerting.

## Endpoint

```
http://localhost:8443/metrics
```

## Available Metrics

### HTTP Request Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `aegisgate_http_requests_total` | Counter | Total HTTP requests | method, endpoint, status |
| `aegisgate_http_request_duration_seconds` | Histogram | Request latency | method, endpoint |
| `aegisgate_active_connections` | Gauge | Active connections | service |

### Rate Limiting Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `aegisgate_rate_limit_hits_total` | Counter | Rate limit triggers | service, client |

### MCP Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `aegisgate_mcp_connections` | Gauge | Active MCP connections | - |
| `aegisgate_mcp_requests_total` | Counter | MCP tool requests | tool, status |

### Tier Usage Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `aegisgate_tier_requests_total` | Counter | Requests by tier | tier |

### Audit Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `aegisgate_audit_events_total` | Counter | Audit events logged | - |

### Security Scan Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `aegisgate_security_scans_total` | Counter | Security scans | type, result |

### Build Info

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `aegisgate_build_info` | Gauge | Build information | version, goversion, platform |

## Example Prometheus Queries

### Request Rate
```promql
rate(aegisgate_http_requests_total[5m])
```

### Error Rate
```promql
rate(aegisgate_http_requests_total{status=~"5.."}[5m])
```

### P95 Latency
```promql
histogram_quantile(0.95, 
  rate(aegisgate_http_request_duration_seconds_bucket[5m]))
```

### Active Connections
```promql
aegisgate_active_connections
```

### Rate Limit Triggers
```promql
rate(aegisgate_rate_limit_hits_total[5m])
```

### MCP Active Connections
```promql
aegisgate_mcp_connections
```

## Recommended Alerts

```yaml
# High error rate
- alert: HighErrorRate
  expr: rate(aegisgate_http_requests_total{status=~"5.."}[5m]) > 0.1
  for: 5m
  severity: critical

# High latency
- alert: HighLatency
  expr: histogram_quantile(0.95, 
    rate(aegisgate_http_request_duration_seconds_bucket[5m])) > 0.5
  for: 5m
  severity: warning

# Rate limiting triggered
- alert: RateLimiting
  expr: rate(aegisgate_rate_limit_hits_total[5m]) > 0
  severity: info

# MCP connection spike
- alert: MCPConnectionSpike
  expr: aegisgate_mcp_connections > 100
  for: 5m
  severity: warning
```

## Grafana Dashboard

See `docs/grafana/dashboard.json` for a pre-configured dashboard.

## Integration

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'aegisgate'
    static_configs:
      - targets: ['localhost:8443']
    metrics_path: /metrics
```

### Pushgateway (optional)

For short-lived deployments:

```go
metrics.PushMetrics("pushgateway:9091", "aegisgate")
```