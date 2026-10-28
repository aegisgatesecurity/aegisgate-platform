# AegisGate MCP Standalone Security Test Harness

Tests the standalone MCP server directly via TCP JSON-RPC protocol.

## Quick Start

```bash
# Start MCP server with demo tools + auth
docker run -d --name synth-mcp \
  --network testlab_synth-net \
  -p 8083:8081 -p 8084:8082 \
  -e MCP_AUTH_TOKEN=test-mcp-token \
  -e MCP_DEMO_TOOLS=true \
  -e MCP_TEST_AGENT=true \
  -e MCP_MAX_SESSIONS=50 \
  aegisgate-mcp:test

# Run tests
python3 mcp_standalone_test.py --host 127.0.0.1 --port 8083 --token test-mcp-token
```

## Test Matrix (22 tests)

| ID | Category | Test |
|----|----------|------|
| MCPA-001 | Auth | No auth token → rejected |
| MCPA-002 | Auth | Wrong auth token → rejected |
| MCPA-003 | Auth | Valid auth token → accepted |
| MCPA-004 | Auth | Authorized tools/list → succeeds |
| MCPA-005 | Auth | Unauthenticated tools/call → rejected |
| MCPA-006 | Auth | Brute force lockout |
| MCPG-001 | Guardrails | Max session enforcement (52 vs 50 limit) |
| MCPG-002 | Guardrails | Rate limit enforcement (70 vs 60 RPM) |
| MCPG-003 | Guardrails | Non-existent tool rejected |
| MCPG-004 | Guardrails | Invalid JSON-RPC method rejected |
| MCPS-001 | Response Scan | PII blocked (SSN + credit card) |
| MCPS-002 | Response Scan | Secrets blocked (AWS key) |
| MCPS-003 | Response Scan | XSS blocked (script tag) |
| MCPS-004 | Response Scan | Prompt injection blocked |
| MCPS-005 | Response Scan | Path traversal passes through (not in 79-pattern subset) |
| MCPS-006 | Response Scan | Clean message passes through (no false positive) |
| MCPT-001 | Tool Poisoning | Clean tool list verified |
| MCPT-002 | Tool Poisoning | Poisoned tool name rejected |
| MCPP-001 | Protocol | Ping response |
| MCPP-002 | Protocol | Malformed JSON rejected |
| MCPP-003 | Protocol | Connection flood handling |
| MCPP-004 | Protocol | Health endpoint |

## Security Layers Tested

The MCP server has a 5-layer security pipeline:
```
auth → signature_verification → guardrails → response_scan → core_handler
```

This harness tests all 5 layers via the `echo` demo tool, which returns user input
verbatim — making it ideal for injecting PII/secrets/XSS/prompt injection and
verifying the scanner blocks the response.

## Notes

- Restart the MCP container before each test run to clear stale session state
- The `echo` tool is only available when `MCP_DEMO_TOOLS=true`
- The test agent (restricted role) is enabled with `MCP_TEST_AGENT=true`
- Guardrail session tracking only activates on `tools/call`, not `initialize`