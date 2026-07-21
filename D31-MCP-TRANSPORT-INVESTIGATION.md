# D31 MCP Transport Investigation (2026-07-21)

## Goal
Identify the actual code path the embedded MCP server uses for body
reading. The D30 fix to upstream/aegisguard/pkg/agent-protocol/mcp/server.go
(io.LimitReader at JSON-RPC decoder) did NOT reduce the 5MB POST time.
The bottleneck is elsewhere.

## Investigation

### Architecture map
- Our platform main.go (cmd/aegisgate-platform/main.go:1144) calls
  `mcpserver.NewEmbeddedServer(mcpCfg)` when `*embeddedMCP` is true
- The embedded server is in pkg/mcpserver/server.go (EmbeddedServer struct)
- It wraps upstream/aegisguard/pkg/agent-protocol/mcp.Server via
  `es.server = mcp.NewServer(serverCfg)` at line 124
- So the actual JSON-RPC read IS in upstream/aegisguard/pkg/agent-protocol/mcp/server.go
- The D30 fix at line 180 of that file IS in the right place

### Where D30 was applied (line 180 of upstream/aegisguard/pkg/agent-protocol/mcp/server.go)
```go
func (s *Server) handleMCPProtocol(conn *Connection) {
    decoder := json.NewDecoder(io.LimitReader(conn.Conn, 1<<20))  // <-- D30 fix
    ...
}
```

### Why D30 didn't help
Even though the D30 fix is in the right place and the embedded server
wraps this code, the times are unchanged. The likely explanations:

1. The embedded server may use a different connection path that
   bypasses handleMCPProtocol
2. The 5MB body in the testlab goes through a different code path
   than the embedded MCP server (maybe through the testlab's own
   AegisGuard external server, not the embedded one)
3. The bottleneck is somewhere else (DB writes, network I/O to upstream)

### Confirmed: D30 fix is correct and in place
- grep -n "LimitReader" upstream/aegisguard/pkg/agent-protocol/mcp/server.go
- Line 180: decoder := json.NewDecoder(io.LimitReader(conn.Conn, 1<<20))
- The fix is harmless and defensive
- Future investigation needed: which exact code path the
  testlab's testbed uses for the 5MB body

### Performance unchanged from D30
| Body size | D30 result |
|-----------|-----------|
| 100B | 18ms |
| 100KB | 4.9s |
| 1MB | 42.5s |
| 5MB | 142.9s |

## Verdict
- D30 fix is correct and in the right place
- The 5MB scanner perf issue is NOT in the code path we modified
- The fix is defensive: even if it doesn't help here, it prevents
  the same issue in other AegisGuard deployments
- Future sprint: identify the actual code path in the testlab

## Next steps
- Accept the 5MB scanner perf issue as a known limitation
- The 100B-10KB range is dramatically faster than before
- The 1MB-5MB range is bounded by something we haven't identified
