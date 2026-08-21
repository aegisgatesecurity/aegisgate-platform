# Distributed Tracing (OpenTelemetry)

AegisGate Platform supports distributed tracing via OpenTelemetry, enabling
end-to-end request visibility across the proxy, dashboard API, and MCP/A2A
protocol handlers.

## Configuration

Tracing is **opt-in** and disabled by default. Enable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGISGATE_TRACING_ENABLED` | `false` | Enable/disable tracing |
| `AEGISGATE_TRACING_EXPORTER` | `otlp` | Exporter type: `otlp` or `stdout` |
| `AEGISGATE_OTLP_ENDPOINT` | `localhost:4317` | OTLP gRPC endpoint (collector) |
| `AEGISGATE_SERVICE_NAME` | `aegisgate-platform` | Service name in spans |
| `AEGISGATE_TRACE_RATIO` | `0.1` | Sampling ratio (0.0–1.0) |
| `AEGISGATE_VERSION` | — | Service version attribute |

## Quick Start

### Docker Compose with Jaeger

```yaml
# docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:1.62
    ports:
      - "16686:16686"  # Jaeger UI
      - "4317:4317"    # OTLP gRPC
      - "4318:4318"    # OTLP HTTP
  aegisgate:
    image: aegisgatesecurity/aegisgate-platform:latest
    environment:
      AEGISGATE_TRACING_ENABLED: "true"
      AEGISGATE_OTLP_ENDPOINT: "jaeger:4317"
      AEGISGATE_SERVICE_NAME: "aegisgate-platform"
    depends_on:
      - jaeger
```

### Kubernetes with Jaeger Operator

```yaml
# Set env vars in your deployment
env:
  - name: AEGISGATE_TRACING_ENABLED
    value: "true"
  - name: AEGISGATE_OTLP_ENDPOINT
    value: "jaeger-collector.observability.svc:4317"
```

### Local Development (stdout)

```bash
AEGISGATE_TRACING_ENABLED=true \
AEGISGATE_TRACING_EXPORTER=stdout \
./aegisgate-platform
```

## Architecture

- **Tracer Provider**: `sdktrace.TracerProvider` with batch exporter
- **Propagator**: W3C Trace Context (`traceparent` header)
- **Sampling**: `TraceIDRatioBased` (configurable)
- **Resource**: Service name + version attributes
- **HTTP Middleware**: Automatically creates server spans for all requests
- **Application Spans**: `tracing.StartSpan(ctx, "operation")` for custom spans

## Integration Points

The tracing middleware wraps both the proxy and dashboard HTTP handlers.
Spans include HTTP method, path, and status code. Trace context is
propagated via W3C Trace Context headers, enabling distributed traces
across service boundaries when combined with MCP/A2A clients that
forward trace context.

## Package

- `pkg/tracing/` — OpenTelemetry initialization, HTTP middleware, span helpers