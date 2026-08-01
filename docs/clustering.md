# AegisGate Platform — Clustering & High Availability

## Overview

AegisGate Platform supports horizontal scaling with 3-5 (or more) instances behind a load balancer for high availability, failover, and increased throughput. The platform's dual-mode architecture (Community = standalone, Professional+ = clustered with PostgreSQL) was designed for this from the start.

## Architecture

```
                    ┌─────────────────┐
                    │  Load Balancer   │
                    │  (Envoy/Nginx/  │
                    │   AWS ALB)      │
                    └────────┬────────┘
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────┴────┐  ┌─────┴────┐  ┌─────┴────┐
        │ AegisGate │  │ AegisGate │  │ AegisGate │
        │  Node 1   │  │  Node 2   │  │  Node 3   │
        │ (node-abc)│  │ (node-def)│  │ (node-ghi)│
        └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
              │              │              │
              │    ┌─────────┴─────────┐    │
              └────┤    PostgreSQL      ├────┘
                   │  (shared state)    │
                   └────────────────────┘
```

## Quick Start

### 1. Set Environment Variables

Each node needs:

```bash
# Required for clustering (Professional+ tier)
export AEGISGATE_DATABASE_URL="postgres://user:pass@pg-host:5432/aegisgate"

# Recommended: stable node ID for cluster identification
export AEGISGATE_NODE_ID="node-1"

# Required: Professional+ license key
export AEGISGATE_LICENSE_KEY="your-license-key"
```

### 2. Start Multiple Instances

```bash
# Node 1
AEGISGATE_NODE_ID=node-1 AEGISGATE_DATABASE_URL=postgres://... ./aegisgate-platform --proxy-port=8080 --dashboard-port=8443 --embedded-mcp

# Node 2
AEGISGATE_NODE_ID=node-2 AEGISGATE_DATABASE_URL=postgres://... ./aegisgate-platform --proxy-port=8080 --dashboard-port=8443 --embedded-mcp

# Node 3
AEGISGATE_NODE_ID=node-3 AEGISGATE_DATABASE_URL=postgres://... ./aegisgate-platform --proxy-port=8080 --dashboard-port=8443 --embedded-mcp
```

### 3. Configure Load Balancer

**Round-robin** (default): Works for all stateless endpoints (`/health`, `/version`, `/api/v1/tier`, `/metrics`, proxy traffic).

**Sticky sessions**: Required for MCP and A2A connections. The platform sends `X-Instance-Id` headers on every response.

#### Envoy Configuration

```yaml
name: aegisgate_cluster
type: ROUND_ROBIN
# Enable sticky routing for MCP/A2A sessions
sticky_session_config:
  cookie_name: "aegisgate_instance"
  ttl: 3600s
# Health check
health_checks:
  - timeout: 5s
    interval: 10s
    healthy_threshold: 2
    unhealthy_threshold: 3
    http_health_check:
      path: /health
      port: 8443
```

#### Nginx Configuration

```nginx
upstream aegisgate {
    least_conn;
    server node-1:8443;
    server node-2:8443;
    server node-3:8443;

    # Sticky routing for MCP connections
    hash $http_x_instance_id consistent;
}

server {
    listen 443 ssl;
    location / {
        proxy_pass https://aegisgate;
        proxy_set_header X-Instance-Id $upstream_http_x_instance_id;
    }
}
```

## State Sharing Matrix

| Component | Community (Standalone) | Professional+ (Clustered) |
|-----------|----------------------|---------------------------|
| **Audit Logs** | File per node | PostgreSQL (shared) |
| **IOC Store** | In-memory per node | PostgreSQL (shared) |
| **RBAC Sessions** | In-memory per node | PostgreSQL (shared) |
| **Correlation Events** | In-memory per node | PostgreSQL (shared) |
| **Attestation Envelopes** | In-memory per node | PostgreSQL (shared) |
| **License** | Local validation | PostgreSQL (shared cache) |
| **Rate Limiting** | Per-node token bucket | PostgreSQL (distributed) |
| **MCP Sessions** | In-memory (sticky routing) | In-memory (sticky routing) |
| **A2A Sessions** | In-memory (sticky routing) | In-memory (sticky routing) |
| **Trust Portal Cache** | 60s TTL per node | 60s TTL per node (converges) |
| **Detection Pipeline** | Stateless per-request | Stateless per-request |
| **IOC Gossip** | Pull from peers | Pull from peers + PostgreSQL |

## Rate Limiting in Clusters

### Community Tier (Per-Node)

Each node maintains its own rate limit counters. A 10K RPM limit becomes 10K per node. For a 3-node cluster, the effective global limit is 30K RPM.

**Mitigation**: Use the load balancer's built-in rate limiting (e.g., Envoy `local_rate_limit`, AWS ALB rate limiting).

### Professional+ Tier (Distributed)

The `DistributedRateLimiter` uses PostgreSQL as a shared counter backend. Each `Allow()` call:
1. Increments this node's counter in PostgreSQL (1-second window)
2. Sums all nodes' counters for the current window
3. Returns `Allow` if the sum is within the rate limit

This ensures a 10K RPM limit is enforced globally across all instances.

**Failover**: If PostgreSQL is unreachable, the limiter automatically falls back to per-node token buckets. Rate limiting continues, just without global coordination.

## Health Checks

### Per-Node Health

```
GET /health HTTP/1.1
Host: node-1:8443
```

```json
{
  "status": "healthy",
  "version": "3.5.0",
    "scanner": { "healthy": true },
    "persistence": { "healthy": true, "backend": "postgresql" },
    "a2a": { "healthy": true, "status": "disabled" }
  }
}
```

### Cluster Health

```
GET /api/v1/cluster/health HTTP/1.1
```

```json
{
  "node_id": "node-1",
  "hostname": "aegisgate-1.prod",
  "version": "3.5.0", "professional",
  "uptime": "72h15m30s",
  "mode": "clustered",
  "peers": {
    "node-2": "healthy",
    "node-3": "healthy"
  },
  "local_health": {
    "proxy": { "healthy": true },
    "persistence": { "healthy": true, "backend": "postgresql" }
  }
}
```

### Response Headers

Every response includes cluster-aware headers:

```
X-Instance-Id: abc123def456
X-Instance-Started-At: 2026-07-24T10:00:00Z
X-Cluster-Mode: clustered
```

## Failover Behavior

### Node Failure

When a node fails:
1. **Load balancer** detects failure via health check (unhealthy threshold: 3 consecutive failures)
2. **Traffic reroutes** to remaining healthy nodes
3. **MCP/A2A sessions** on the failed node reconnect to a healthy node (sticky routing redirects)
4. **No data loss** — all persistent state is in PostgreSQL
5. **IOC gossip** continues — remaining nodes still serve and receive IOC manifests

### PostgreSQL Failure

When PostgreSQL is unavailable:
1. **Automatic fallback** to in-memory storage (Community-tier behavior)
2. **Rate limiting** falls back to per-node token buckets
3. **Audit logs** fall back to file-based storage
4. **IOC store** switches to in-memory with local file persistence
5. **RBAC sessions** become per-node (existing sessions survive, new sessions are local)

### Network Partition

During a network partition:
1. **Each partition** continues operating independently (in-memory fallback)
2. **Rate limiting** may allow more requests than configured (per-node fallback)
3. **When partition heals**, PostgreSQL reconnects and distributed rate limiting resumes
4. **IOC gossip** resumes between reunited nodes

## Performance at Scale

Based on k6 break testing (v3.6.0, single node):

| VUs | Requests | p50 | p95 | p99 | Error Rate |
|-----|----------|---------|---------|---------|------------|
| 100 | 108K | 1.74ms | 5.48ms | 9.17ms | 0.00% |
| 200 | 362K | 1.51ms | 6.77ms | 13.32ms | 0.00% |
| 500 | 938K | 4.59ms | 16.51ms | 36.09ms | 0.00% |
| 1,000 | 1.5M | 22.67ms | 46.05ms | 72.08ms | 0.00% |
| 2,000 | 819K | 69.25ms | 122.80ms | 152.39ms | 0.00% |

**Projected cluster performance (3 nodes, round-robin):**
- 3x throughput: ~45K RPS at p95 < 50ms
- 5x throughput: ~75K RPS at p95 < 100ms
- Near-linear scaling for stateless operations (detection pipeline, proxy)

## Configuration Reference

### Environment Variables

| Variable | Purpose | Default | Required |
|----------|---------|---------|----------|
| `AEGISGATE_DATABASE_URL` | PostgreSQL connection string | (none) | Yes (clustered) |
| `AEGISGATE_NODE_ID` | Stable node identifier | (random) | Recommended |
| `AEGISGATE_LICENSE_KEY` | Professional+ license | (none) | Yes (clustered) |
| `AEGISGATE_IOC_SHARE` | Enable IOC manifest serving | `false` | No |
| `AEGISGATE_IOC_RECEIVE` | Enable IOC peer fetching | `false` | No |

### PostgreSQL Schema

The clustering package automatically creates:

```sql
CREATE TABLE IF NOT EXISTS cluster_rate_limits (
    key       TEXT    NOT NULL,
    window    BIGINT  NOT NULL,
    node_id   TEXT    NOT NULL,
    count     INT     NOT NULL DEFAULT 1,
    PRIMARY KEY (key, window, node_id)
);
```

Existing PostgreSQL tables (created by `PostgresStore`):
- `ioc_fingerprints` — shared IOC data
- `audit_events` — shared audit log
- `rbac_agents`, `rbac_sessions` — shared RBAC state
- `correlation_events` — shared correlation data
- `attestation_envelopes` — shared attestation data

## Deployment Checklist

- [ ] PostgreSQL 14+ deployed and accessible from all nodes
- [ ] `AEGISGATE_DATABASE_URL` set on all nodes
- [ ] `AEGISGATE_NODE_ID` set to unique value per node
- [ ] Professional+ license key on all nodes
- [ ] Load balancer health check pointing to `/health` on each node
- [ ] Sticky sessions enabled for MCP/A2A traffic
- [ ] IOC gossip enabled if using federated IOC sharing
- [ ] Monitoring configured for `/api/v1/cluster/health`
- [ ] Rate limiting strategy decided (per-node for Community, distributed for Professional+)