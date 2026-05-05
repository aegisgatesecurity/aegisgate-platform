# A2A Guardrails Technical Specification

## Overview
This document defines the technical control requirements for the A2A Protocol security module. It maps each of the ten A2A guardrails to concrete implementation details, Go interfaces, data flows, and integration points with the existing AegisGate security infrastructure.

## Guardrails

| ID | Guardrail | Description | Technical Controls |
|----|-----------|-------------|--------------------|
| **G1** | Authentication | Verify the identity of agents before any interaction. | - Use mutual TLS with X.509 certificates.\n- Optional JWT token exchange for short‑lived session tokens.\n- `AuthProvider` interface (see below). |
| **G2** | Message Integrity | Ensure messages are not tampered in transit. | - Sign each A2A message payload with Ed25519.\n- Include signature header `A2A-Signature`.\n- Verify signatures on receive. |
| **G3** | Capability Enforcement | Enforce least‑privilege capabilities per agent. | - Capability registry stored in Redis/DB.\n- `CapabilityEnforcer` middleware checks allowed actions per request. |
| **G4** | Input Validation | Validate all inbound data according to JSON schema. | - JSON schema definitions per A2A message type.\n- `Validator` uses `github.com/xeipuuv/gojsonschema`. |
| **G5** | Rate Limiting | Prevent abuse of the A2A endpoints. | - Token bucket per agent ID.\n- Configurable limit (default 100 req/min). |
| **G6** | Task ACLs | Restrict which agents can invoke which tasks. | - ACL entries stored in DB.\n- `TaskACL` checks performed in `TaskHandler`. |
| **G7** | Output Filtering | Remove disallowed data from responses. | - Output sanitizer strips unsafe fields based on the requesting agent's clearance level. |
| **G8** | Agent Registry & Trust Scoring | Maintain a registry of known agents and assign trust scores. | - Registry service with CRUD API.\n- Trust score computed from reputation, behavior metrics. |
| **G9** | Notification Verification | Authenticate push notifications. | - HMAC signed notification payloads.\n- Verify signature on receipt. |
| **G10** | Artifact Validation | Verify integrity of artifacts exchanged between agents. | - SHA‑256 checksum header `A2A-Checksum`.\n- Optional virus scan via ClamAV integration. |

## Interfaces

```go
// AuthProvider validates authentication credentials.
type AuthProvider interface {
    Authenticate(ctx context.Context, cert tls.Certificate) (AgentID, error)
    VerifyToken(ctx context.Context, token string) (AgentID, error)
}

// CapabilityEnforcer checks if an agent can perform a capability.
type CapabilityEnforcer interface {
    IsAllowed(agent AgentID, capability string) (bool, error)
}

// Validator validates incoming JSON payloads against a schema.
type Validator interface {
    Validate(messageType string, payload []byte) error
}

// RateLimiter provides per‑agent request throttling.
type RateLimiter interface {
    Allow(agent AgentID) bool
}
```

## Data Flow
1. **Incoming Request** → TLS termination → `AuthProvider` → `CapabilityEnforcer` → `Validator` → `RateLimiter` → Business logic.
2. **Outgoing Response** → `OutputFilter` → Signature (`Message Integrity`) → Optional `Checksum`.

## Integration Points
- **MCP Guardrails**: Reuse existing guardrail middleware where applicable (e.g., rate limiting, ACLs).
- **Configuration**: All guardrail parameters are configurable via `config/a2a.yaml` and can be overridden per‑environment.
- **Metrics**: Export Prometheus metrics for each guardrail (e.g., auth failures, rate‑limit hits).

## Open Tasks
- Implement `AuthProvider` using the existing PKI infrastructure.
- Define JSON schemas for all A2A message types.
- Add unit tests covering each guardrail implementation.
- Update CI pipeline to lint and test the new `pkg/a2a` package.

---
*Document generated on $(date)*
