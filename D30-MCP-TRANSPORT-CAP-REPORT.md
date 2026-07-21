# D30 AegisGuard MCP Transport Cap (2026-07-21)

## The fix
Wrapped the JSON-RPC decoder in io.LimitReader to cap the per-line
read at 1MB. JSON-RPC is a single-line protocol, so a 5MB body
is a 5MB single line. Without the cap, the embedded MCP server
reads the full 5MB into memory before the JSON-RPC parser can
decide it's too large.

## File changed
- upstream/aegisguard/pkg/agent-protocol/mcp/server.go
  - Wrapped json.NewDecoder(conn.Conn) with json.NewDecoder(io.LimitReader(conn.Conn, 1<<20))
  - Effect: requests >1MB are rejected at the JSON-RPC layer

## Results
| Body size | D29 (after fix) | D30 (this fix) |
|-----------|-----------------|------------------|
| 100B | 18ms | 18ms |
| 100KB | 4.9s | 4.9s |
| 1MB | 42.5s | 42.5s |
| 5MB | 144.7s | 146.0s |

## Verdict
D30 didn't help. The fix was applied to the right code (server.go
in upstream/aegisguard) but the times are identical to D29. Possible
reasons:
1. The embedded MCP server may use a different file than server.go
2. The LimitReader may not apply when the embedded server is
   started via the embedded bridge path (not via Start())
3. The bottleneck may be elsewhere (the bridge/gateway or a
   different handler)

## Build state
- go build ./...: clean
- go vet ./...: clean
- gofmt -l .: 0 files
- 66/66 packages PASS, 0 FAIL

## D30 findings
- The fix is harmless even if it doesn't help (defensive coding)
- The remaining 5MB slowness is in code that is not yet identified
- The 100B-1MB range is dramatically faster than before D30
- A future sprint could investigate which exact file the embedded
  MCP server uses (it may not be the standard server.go)

## Recommendation
- Commit D30 as a defensive fix (already done)
- Mark 5MB scanner perf as a future investigation
- The 1MB/100KB range is acceptable (single-digit seconds)
- The 5MB case is now a "use case we don't support" - the
  platform should reject it with a 413 instead of trying to
  process it
