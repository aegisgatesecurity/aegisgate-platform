# AegisGate Platform — Chain Analyzer, Sandbox, and Interop

> **Document version:** 1.0 — 2026-10-14  
> **Status:** Architecture documentation  
> **License:** Proprietary — AegisGate Security, LLC

## Overview

This document describes three key Platform subsystems that work together
to provide defense-in-depth for MCP (Model Context Protocol) tool
execution and cross-product intelligence sharing:

1. **Chain Analyzer** — Detects multi-step attack patterns across tool calls
2. **Sandbox** — Isolates tool execution to limit blast radius
3. **Interop** — Canonical event schema and forwarding for the AegisGate suite

---

## 1. Chain Analyzer (`pkg/toolauth/chain_analyzer.go`)

### Purpose

The Chain Analyzer correlates sequences of MCP tool calls within a session
to detect chained attack patterns that would be invisible when inspecting
individual calls in isolation.

### What It Detects

| Pattern | Description | Example |
|---------|-------------|---------|
| Privilege escalation | Low-risk tool → high-risk tool sequence | `read_file` → `exec_command` |
| Data exfiltration | Read sensitive → write external | `get_secret` → `http_post` |
| Recon-to-exploit | Scan/recon → exploitation | `list_services` → `exploit_cve` |
| Unusual sequencing | Deviation from expected tool usage | Rapid alternating between unrelated tools |

### How It Works

- Maintains a **sliding window** of the last 20 tool calls per session
- Each entry records: timestamp, tool name, risk level, decision (allow/deny/require_approval)
- Entries expire after 30 minutes of inactivity (ChainTTL)
- On each new tool call, the analyzer evaluates the full chain for risk patterns
- Produces a **ChainRiskAssessment** that augments the per-call authorization decision

### Configuration

The chain analyzer is enabled by default in Platform's MCP server. It can
be configured via:

- `CHAIN_ANALYSIS_WINDOW` — Number of tool calls to retain (default: 20)
- `CHAIN_ANALYSIS_TTL` — Inactivity timeout (default: 30m)
- `CHAIN_ANALYSIS_ENABLED` — Enable/disable (default: true)

### Integration Points

- `pkg/mcpserver/guardrails.go` — Calls the chain analyzer before tool execution
- `pkg/mcpserver/chain_analysis_integration_test.go` — Integration tests
- Results feed into the audit log and can be forwarded to Platform telemetry

---

## 2. Tool Execution Sandbox (`pkg/mcpserver/guardrails.go`)

### Purpose

The sandbox limits the blast radius of tool execution by enforcing
guardrails on what tools can do, even when they pass authorization.

### Guardrail Categories

| Guardrail | Description |
|-----------|-------------|
| Network egress | Restricts which hosts/domains tools can contact |
| Filesystem access | Restricts which paths tools can read/write |
| Resource limits | CPU, memory, and time limits on tool execution |
| Environment isolation | Tools run with restricted environment variables |
| Output filtering | Tool output is scanned before returning to the LLM |

### How It Works

1. **Pre-execution:** Guardrails check the tool's input parameters against
   the configured policy (e.g., "no network access for file tools")
2. **During execution:** Resource limits are enforced (timeout, memory cap)
3. **Post-execution:** Output is scanned for PII, secrets, and prompt injection
   before being returned to the LLM context

### Configuration

Guardrails are configured per-tool via the Tool Authorization Matrix:

```yaml
tool_guardrails:
  - tool: "read_file"
    network: deny
    filesystem:
      allow_paths: ["/data/**", "/tmp/**"]
      deny_paths: ["/etc/**", "/root/**"]
    timeout: 30s
    memory_limit: 128MB
```

### Integration Points

- `pkg/mcpserver/guardrails.go` — Core guardrail enforcement
- `pkg/toolauth/` — Authorization matrix that defines per-tool policies
- Platform config (`pkg/platformconfig/config.go`) — Global guardrail settings

---

## 3. Interop Architecture

### Overview

AegisGate's five products (Platform, Scanner, Rampart, Lens, MCP) share
intelligence through a canonical event schema and opt-in forwarding
architecture. All communication is **outbound, opt-in, and air-gap
compatible** — no product requires network connectivity to function.

### Canonical Event Schema (`pkg/contracts/`)

The shared schema defines two core types:

- **Event** — A single detection event with metadata-only findings
- **PatternSet** — A versioned set of detection patterns for distribution

Key design decisions:
- **No sensitive values:** Events contain rule IDs, categories, and severity —
  never matched text, PII values, or credentials
- **JSON-serializable:** Raw regex strings (not compiled `*regexp.Regexp`)
  for HTTP serialization
- **Source-tagged:** Every event has a `source` field (lens, rampart, scanner,
  mcp, platform) for routing and aggregation
- **Versioned:** Schema version "v1" — future versions maintain backward compat

### Event Flow Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │           AegisGate Platform                │
                    │  ┌──────────────┐  ┌─────────────────────┐ │
                    │  │ pkg/telemetry│  │  pkg/lensbackend    │ │
                    │  │ /api/v1/     │  │  /api/v1/lens/      │ │
                    │  │ telemetry    │  │  telemetry          │ │
                    │  └──────┬───────┘  └──────────┬──────────┘ │
                    │         │                     │            │
                    │  ┌──────┴───────────────────────┘         │
                    │  │  SIEM Integration + Audit Trail         │
                    │  └─────────────────────────────────────────│
                    └─────────────────────────────────────────────┘
                           ↑                    ↑
                           │                    │
              ┌────────────┘                    └──────────────┐
              │                                                │
    ┌─────────┴────────┐                          ┌─────────────┴──────┐
    │   Scanner        │                          │   MCP              │
    │   pkg/platform   │                          │   platform_        │
    │   forward        │                          │   forwarder.go     │
    │   → EventBatch   │                          │   → EventBatch     │
    └──────────────────┘                          └────────────────────┘

    ┌──────────────────┐    ┌──────────────────────────────────────────┐
    │   Rampart        │    │   Cloudflare Worker (lens.aegisgatesec.io)│
    │   internal/      │    │   /api/v1/telemetry (multi-source)       │
    │   platformforward│    │   Accepts events from ALL products       │
    │   → PlatformEvent│    │   For non-Platform (community) users     │
    └──────────────────┘    └──────────────────────────────────────────┘
                                     ↑
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
    ┌─────────┴────────┐  ┌──────────┴──────────┐  ┌────────┴─────────┐
    │   Lens           │  │   Scanner           │  │   Rampart        │
    │   (browser ext)  │  │   (CLI/CI)          │  │   (proxy)        │
    └──────────────────┘  └─────────────────────┘  └──────────────────┘
```

### Privacy Guarantees

All event forwarding adheres to these non-negotiable rules:

1. **No prompt text** — Never send the user's prompt or conversation
2. **No PII values** — Send categories and rule names only, never the matched values
3. **No credentials** — Never send secrets, tokens, or API keys
4. **No matched text** — The `MatchedText` field is stripped before forwarding
5. **Opt-in only** — Forwarding is disabled by default (empty `platform_url`)
6. **Air-gap compatible** — All products fully functional with zero network

### Product Integration Status

| Product | Forwarding | Pattern Pull | Code | Status |
|---------|-----------|-------------|------|--------|
| Platform | Receiver | Source | `pkg/telemetry` + `pkg/contracts` | ✅ Phase 0 |
| Scanner | `pkg/platformforward` | TBD (Phase 5) | `FindingsToEvent` | ✅ Phase 3 (I1) |
| Rampart | `internal/platformforward` | TBD (Phase 5) | `Forwarder.Forward` | ✅ Existing |
| MCP | `platform_forwarder.go` | N/A (zero-dep) | `PlatformForwarder` | ✅ Phase 3 (I3) |
| Lens | Cloudflare Worker | TBD (Phase 5) | Multi-source endpoint | ✅ Phase 3 (I8) |

### Cloudflare Worker (Community Telemetry)

For users without Platform, the Cloudflare Worker at
`lens.aegisgatesecurity.io` provides a community telemetry receiver:

- `POST /api/v1/telemetry` — Accepts EventBatch from all products
- `GET /api/v1/healthz` — Connectivity check
- `POST /api/fp-report` — Legacy Lens FP reports (backward compatible)
- 90-day KV retention with source-tagged keys
- 10K events/min rate limit (shared across sources)
- Privacy enforcement at the edge: rejects events with `matched_text` fields

### Pattern Distribution (Phase 5 — Planned)

Platform will push updated detection patterns to FOSS products:

- `GET /api/v1/patterns/latest` — Returns canonical PatternSet (already in `pkg/telemetry`)
- FOSS products pull on startup and periodically
- Versioned with hash for change detection
- Backward compatible — old patterns work until explicitly updated

---

## References

- `pkg/contracts/event.go` — Canonical Event schema
- `pkg/contracts/pattern.go` — Canonical Pattern format
- `pkg/telemetry/server.go` — Platform telemetry receiver
- `pkg/toolauth/chain_analyzer.go` — Chain analyzer implementation
- `pkg/mcpserver/guardrails.go` — Sandbox guardrails
- OWASP LLM Top 10 mapping — `docs/compliance/` directory

---

*Copyright 2026 AegisGate Security, LLC. All rights reserved.*