# MCP E2E Test Preparation Checklist

## Prerequisites Checklist

### 1. MCP Server Availability ✅ REQUIRED

The E2E tests need a real MCP server to test against. **Options:**

#### Option A: Built-in Embedded Server (Recommended)
- **Status**: Already implemented in main.go with `--embedded-mcp` flag
- **Command**: The platform already starts `./aegisgate-platform --embedded-mcp`
- **Port**: MCP server listens on port 8081 (configurable)
- **Tools**: Built-in tools (echo, filesystem read/write, HTTP request)

#### Option B: External MCP Server
If testing against external server:
- [ ] MCP server binary available
- [ ] Server configured to listen on known port
- [ ] Server has at least one tool registered
- [ ] Server accepts JSON-RPC connections

### 2. Test Environment Setup

| Item | Status | Notes |
|------|--------|-------|
| Platform binary | ✅ | `go build` produces working binary |
| Data directory writable | ✅ | Configured to use temp directory |
| Audit directory writable | ✅ | Configured to use temp directory |
| MCP port available | ✅ | Port 28081 (or configured test port) |
| JSON-RPC library | ✅ | Native Go implementation |

### 3. Test Scenarios to Implement

#### Scenario 1: MCP Initialize
```
Request:  {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
Expected: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{...}}}
```

#### Scenario 2: Tool List
```
Request:  {"jsonrpc":"2.0","id":2,"method":"tools/list"}
Expected: {"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}
```

#### Scenario 3: Tool Call (Authorized)
```
Request:  {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"test"}}}
Expected: {"jsonrpc":"2.0","id":3,"result":{"content":[...]}}
```

#### Scenario 4: Tool Call (Blocked by Guardrails)
```
Request:  {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"/etc/passwd","content":"..."}}}
Expected: Blocked or error response (depends on guardrail config)
```

#### Scenario 5: Audit Trail Verification
- After MCP operations, verify audit events written to `/api/v1/audit`

### 4. Current Implementation Status

From code analysis:

```go
// In main.go:
// - Embedded server starts with --embedded-mcp flag ✓
// - Tier-aware guardrails applied ✓
// - Built-in tools registered ✓
// - Scanner connects to embedded server ✓
```

**Current Gap**: Need to implement actual JSON-RPC MCP client in E2E test

### 5. Artifacts Needed From You

#### If using Built-in Server (Recommended):
- [ ] **Confirmation** that built-in tools are sufficient for testing
- [ ] **Tool whitelist** - which tools should Community tier have access to?
  - Current: echo, filesystem_read, filesystem_write, http_request
  - Need to verify which are actually allowed

#### If using External Server:
- [ ] **MCP server binary** or Docker image
- [ ] **Configuration** for the server (mcp.json or similar)
- [ ] **Tool manifest** - list of available tools for E2E validation

### 6. MCP Protocol Details

#### Connection
- **Transport**: TCP socket
- **Protocol**: JSON-RPC 2.0
- **Message Delimiter**: Newline (`\n`)
- **Encoding**: UTF-8 JSON

#### Message Format
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize|tools/list|tools/call|...",
  "params": {...}
}
```

#### Response Format
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {...}
}
// OR
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {"code": -32600, "message": "..."}
}
```

### 7. E2E Test File Plan

```go
// tests/e2e/mcp_e2e_test.go
// Test scenarios:
// 1. TestMCPInitialize - Verify handshake works
// 2. TestMCPToolList - Verify tools are returned
// 3. TestMCPToolCall_Echo - Simple authorized call
// 4. TestMCPToolCall_Guardrail - Blocked call
// 5. TestMCPAuditTrail - Verify audit logging
```

### 8. Dependencies

#### Go Libraries Needed:
```go
// Standard library only:
- encoding/json
- net (for TCP connection)
- fmt, time, testing
```

#### No External MCP Client Libraries Required
The E2E test will implement a minimal JSON-RPC client:
```go
func sendMCPRequest(conn net.Conn, method string, params interface{}) (*MCPResponse, error)
```

---

## 🎯 ACTION ITEMS FOR YOU

1. **Confirm test approach**: Built-in embedded server or external?
2. **If external**: Provide MCP server artifacts
3. **Tool whitelist**: Which tools should Community tier E2E test?
4. **Guardrail expectations**: What should trigger blocks?

## ✅ READY WHEN YOU ARE

Once you provide the above, I can implement the complete MCP E2E test suite with:
- Native JSON-RPC client
- All 5 test scenarios
- Audit trail verification
- Guardrail validation

**Estimated implementation time**: 2-3 hours