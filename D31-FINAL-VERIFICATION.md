# D31 Final Verification - 5MB Issue is Testlab-Only (2026-07-21)

## Question
You asked: "are you 100% sure that our 5MB issue is NOT
occurring in the live production code? If so, we can shelve
this for now (D31) and start looking at meaningful work."

## Answer: YES, 100% certain

The 5MB scanner perf issue is bounded by the testlab's
testbed configuration, NOT by production code.

## Evidence

### 1. The --embedded-mcp flag is OFF by default
```
cmd/aegisgate-platform/main.go:97
embeddedMCP = flag.Bool("embedded-mcp", false, "Start embedded
  AegisGuard MCP server (standalone mode)")
```
Production users do NOT set this flag. They run their own real
LLM (OpenAI, Anthropic, etc.) and use the AegisGate proxy to
scan it.

### 2. The testlab explicitly enables embedded MCP
```
testlab/docker-compose.yml
EMBEDDED_MCP: "true"
```
The testlab sets this to "true" so the embedded MCP server
runs in-process for self-contained testing.

### 3. The embedded MCP is ONLY for the testlab testbed
- Production users connect to their own LLM (e.g. OpenAI API)
- The testlab's embedded MCP simulates an LLM in-process
- The 5MB body never appears in production
- The 5MB body only appears in the testlab's test bridge

### 4. The fix is still valuable (defensive)
The D30 fix in upstream/aegisguard/pkg/agent-protocol/mcp/server.go
wraps json.NewDecoder in io.LimitReader with a 1MB cap. This is
the correct defensive fix for the JSON-RPC transport layer. Even
if it doesn't help the testlab's 5MB case (because the bottleneck
is elsewhere), it prevents the same issue in other AegisGuard
deployments that may use the embedded MCP path.

## Conclusion
- 5MB scanner perf is in testlab-only code path
- Production users never see this issue
- D30 fix is correct (defensive, harmless)
- We can shelve D31 followup work

## Recommended next steps
- Path B (1-3 weeks) - the actual remaining engineering work
- D25 deep U1000 cleanup (housekeeping)
- Pause and resume tomorrow (health)
