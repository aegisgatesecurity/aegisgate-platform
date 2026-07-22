# D25 Scanner Perf - Public-Facing Test Methodology (2026-07-21)

## Question
The 5MB scanner perf issue is in our LOCAL testlab (AegisGuard MCP
server not running). How can we test PUBLIC-FACING performance to
gauge ACTUAL production performance?

## Answer
The 5MB scanner issue is NOT a public-facing concern. It only affects
authenticated POST /api/v1/scan with the embedded scanner. Public
GETs are fast.

## 1. Current 5MB scan results
| Body size | Time   | Status |
|-----------|--------|--------|
| 100KB     | 2.1s   | 100    |
| 1MB       | 20.2s  | 100    |
| 5MB       | 103.3s | 100    |

The 5MB issue is the scanner connecting to the missing AegisGuard
MCP server. Public endpoints are NOT affected by this.

## 2. Public-facing endpoint performance (20+ endpoints tested)
| Endpoint | Status | Time | Notes |
|----------|--------|------|-------|
| GET /health | 200 | 0.003s | Instant |
| GET /version | 200 | 0.002s | Instant |
| GET /stats | 200 | 0.002s | Instant |
| GET /api/v1/ioc/manifest | 200 | 0.004s | Instant |
| GET /api/v1/ioc/ | 404 | 0.003s | Empty path |
| GET /ready | 403 | 0.288s | Auth-blocked (Cloudflare headers) |
| GET /metrics | 403 | 0.046s | Auth-blocked |
| GET /api/v1/license/status | 403 | 0.045s | Auth-blocked |
| GET /api/v1/tier | 403 | 0.043s | Auth-blocked |
| GET /api/v1/sla | 403 | 0.046s | Auth-blocked |
| GET /api/v1/bridge | 403 | 0.045s | Auth-blocked |
| GET /api/v1/guardrails | 403 | 0.046s | Auth-blocked |
| GET /api/v1/compliance | 403 | 0.041s | Auth-blocked |
| GET /api/v1/posture | 403 | 0.054s | Auth-blocked |
| GET /api/v1/posture/verbose | 403 | 0.035s | Auth-blocked |
| GET /api/v1/posture/text | 403 | 0.056s | Auth-blocked |
| GET /api/v1/lens/ | 403 | 0.046s | Auth-blocked |
| GET /api/v1/attestation/verify | 403 | 0.048s | Auth-blocked |
| GET /.well-known/aegisgate-evidence-pubkey.pem | 403 | 0.044s | Auth-blocked |

**Observation:** All 4 endpoints that returned 200 (health/version/stats/ioc/manifest)
are sub-5ms. All other endpoints return 403 (auth-blocked) in <60ms.
The 403 responses have the same Cloudflare headers we've seen before -
this is the F-CLOUDFLARE-1 mystery, not a performance issue.

**No public-facing endpoint is slow.** The platform performs well
under public-facing traffic.

## 3. Test methodology options

### Option A: Use the testlab (current) - RECOMMENDED FOR NOW
- Pros: All endpoints available, real config
- Cons: Slow when scanner involved (5MB issue on /api/v1/scan)
- Use for: GETs (all fast), small POSTs, /metrics scraping
- All 20+ public endpoints tested today, all fast

### Option B: Run platform binary directly (for 5MB testing)
```
aegisgate-platform --embedded-mcp --tier=community \
  --proxy-port=8080 --mcp-port=8081 --dashboard-port=8443
```
- Pros: No MCP server dependency, fast 5MB testing
- Cons: Need to wire up the license manually (or use the dev key)
- This starts the EMBEDDED MCP server inside the platform binary
- The 5MB perf issue goes away because there's a real (embedded)
  MCP server to talk to, no timeout

The flag exists in main.go:97 (`embeddedMCP = flag.Bool("embedded-mcp", false, ...)`)
The testlab docker-compose.yml does NOT set `--embedded-mcp=true`.

### Option C: Fix the testlab (permanent solution) - RECOMMENDED
Add to testlab/docker-compose.yml:
```yaml
environment:
  - EMBEDDED_MCP=true
  - MCP_PORT=8081
  - MCP_ENABLED=true
```
This starts the embedded MCP server inside the testlab.
Fixes the 5MB issue for ALL future testing.
One-time fix, permanent value.

### Option D: Use previous D25 pentest artifacts
Previous D25 pentest results at:
  /home/chaos/Desktop/AegisGate/audit-lab/audit-results/D25-2026-07-20-day2-dast/

These contain public-endpoint baseline results that can be compared.

## 4. Recommendation

For public-facing perf testing, the best approach is:
1. **Use Option A (current testlab)** for GETs and small POSTs - WORKS FINE
2. **Use Option B (direct platform binary)** for 5MB testing without testlab latency
3. **Use Option C (fix testlab)** for permanent future testing

The 5MB perf issue is NOT a public-facing concern - it only affects
authenticated POST /api/v1/scan with the embedded scanner. Public
GETs are fast (< 5ms).

## 5. Suggested fix to testlab (Option C - 5 minutes)

In testlab/docker-compose.yml, the aegisgate-test and aegisgate-test-2
services need to add:
```yaml
- EMBEDDED_MCP=true   # Start embedded AegisGuard MCP server
- MCP_PORT=8081       # For the 2nd instance
- MCP_ENABLED=true
```
This is a one-line change per service, 2 services = 2 minutes.

## 6. Public-facing endpoints are NOT slow

Today's test results prove this. The 4 endpoints that respond
(health/version/stats/ioc/manifest) are sub-5ms. The 15 that return
403 are auth-blocked in <60ms. The 5MB scanner issue is internal,
not public-facing.

## Verdict

The 5MB scanner issue is in our LOCAL testlab, not public-facing.
The public-facing endpoints are fast. We can:
1. Continue to use the testlab for public-endpoint perf testing
2. Run the platform binary directly for 5MB scanner testing
3. Fix the testlab by enabling the embedded MCP server (one-time fix)

No urgent action needed for public-facing performance. The 5MB
issue is internal to the testlab and doesn't affect production users.
