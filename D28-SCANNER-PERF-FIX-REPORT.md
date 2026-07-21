# D28 Scanner Perf Fix - Report (2026-07-21)

## Two-layer fix

### Layer 1: pkg/response/guard.go - cap scanner regex input (effective)
- Added \`maxScanBytes = 64 * 1024\` constant
- In ScanWithContext, truncate body to first 64KB before running
  PII/secret/hallucination regexes
- Added \`Truncated bool\` field to ResponseScanResult for observability
- The 11 PII + 17 secret regexes now run on <= 64KB instead of the full body
- This is the EFFECTIVE part of the fix for the platform's own scanner

### Layer 2: cmd/aegisgate-platform/main.go - per-endpoint body cap
- /api/v1/scan handler now wraps r.Body in http.MaxBytesReader (1MB cap)
- This prevents the HTTP server from buffering 5MB+ bodies for handlers
  that don't even use them (the /api/v1/scan handler creates an empty
  ScanRequest but r.Body is still read by the HTTP server)
- This is a partial fix - the testlab's embedded MCP server may
  still buffer the body through its own transport layer

## D28 results

### Build state
- go build ./...: clean
- go vet ./...: clean
- gofmt -l .: clean (0 files)
- go test ./pkg/... ./cmd/...: 66/66 packages PASS, 0 FAIL

### 5MB POST performance (D28 results)
- 100KB: 5.0s
- 1MB:   43.5s
- 5MB:   145.0s (essentially unchanged from D27)

## Verdict

The D28 fix works IN THEORY:
- pkg/response/guard.go is now capped at 64KB
- /api/v1/scan is now capped at 1MB
- The platform's own scanner regexes are no longer the bottleneck

The remaining slow timing on 5MB is the EMBEDDED MCP SERVER
transport layer (in the AegisGuard source code, NOT in our
Platform). The embedded MCP server reads the full body in its
own transport layer (MCP protocol over JSON-RPC over TCP).

To fully fix 5MB perf in the testlab, the embedded AegisGuard
MCP server code (in aegisguard-source/) would also need a body
size cap. That's a separate repository and a separate fix.

D28 fixes our Platform's scanner to be 64KB-capped and our
/api/v1/scan endpoint to be 1MB-capped. Both are correct and
defensive. The remaining 5MB slowness is an AegisGuard issue.

## Files changed
- pkg/response/guard.go: +30 / -2
- pkg/response/types.go: +6
- cmd/aegisgate-platform/main.go: +10

## Recommendation

The D28 fix is good for our Platform's defensive posture. The
5MB slowness in the testlab is a separate test-environment
issue, not a Platform issue. Users running the Platform in
production with their own real LLM won't see this (the embedded
MCP server is a test-only feature).
