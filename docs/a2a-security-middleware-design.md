# A2A Security Middleware Design

## Introduction
The A2A Security Middleware provides a pluggable layer that enforces the ten A2A guardrails defined in the **Technical Control Requirements** document. It integrates with the existing AegisGate MCP guardrail framework and offers a unified API for agents communicating via the A2A protocol.

## High‑Level Architecture
```
+-------------------+       +-------------------+       +-------------------+
|   Agent (A2A)    | <---> |   A2A Server      | <---> |   AegisGate Core  |
|   (adk-go)      |       |   (pkg/a2a)       |       |   (pkg/mcp)       |
+-------------------+       +-------------------+       +-------------------+
        |   ^                         |   ^
        |   |                         |   |
        v   |                         v   |
   AuthProvider   CapabilityEnforcer   RateLimiter
        |                                 |
        v                                 v
   +-------------------------------------------+
   |  Guardrail Middleware Chain (pipeline)    |
   +-------------------------------------------+
        |   |   |   |   |   |   |   |   |   |
        v   v   v   v   v   v   v   v   v   v
   G1  G2  G3  G4  G5  G6  G7  G8  G9  G10
```

## Core Components
| Component | Responsibility | Key Interfaces |
|-----------|----------------|----------------|
| **AuthProvider** | Mutual‑TLS and JWT authentication of agents. | `AuthProvider` (see Technical Spec) |
| **CapabilityEnforcer** | Checks agent capabilities against a registry. | `CapabilityEnforcer` |
| **Validator** | JSON‑schema validation for incoming A2A messages. | `Validator` |
| **RateLimiter** | Token‑bucket per‑agent request throttling. | `RateLimiter` |
| **TaskACL** | Enforces which agents can invoke which tasks. | `TaskACL` (internal) |
| **OutputFilter** | Sanitises responses based on clearance. | `OutputFilter` |
| **SignatureVerifier** | Verifies Ed25519 signatures on inbound messages. | `SignatureVerifier` |
| **ChecksumValidator** | Validates `A2A-Checksum` header for artifacts. | `ChecksumValidator` |
| **NotificationVerifier** | HMAC verification for push notifications. | `NotificationVerifier` |
| **AgentRegistry** | Stores agent metadata and computed trust scores. | `AgentRegistry` |

## Middleware Pipeline
1. **TLS termination** – Handled by the HTTP server (standard Go `net/http`).
2. **AuthProvider** – Extract client cert, map to `AgentID`.
3. **RateLimiter** – Enforce per‑agent request quota.
4. **CapabilityEnforcer** – Verify required capability for the endpoint.
5. **Validator** – JSON‑schema validation of the request payload.
6. **TaskACL** – Ensure the agent is allowed to invoke the requested task.
7. **SignatureVerifier** – Validate the `A2A-Signature` header.
8. **Business Logic** – Delegates to the underlying A2A service implementation.
9. **OutputFilter** – Strip disallowed fields from the response.
10. **ChecksumValidator** – Verify any attached artifact checksums.
11. **NotificationVerifier** – Validate any outbound push notifications before sending.

## Integration with AegisGate
- The middleware registers itself as an HTTP handler under `/a2a/` using the existing **router** from `pkg/router`.
- Guardrail metrics are exposed via the existing Prometheus exporter (`pkg/metrics`).
- Configuration lives in `config/a2a.yaml` and is loaded by the central config loader (`pkg/config`).
- The middleware re‑uses the **logging** and **tracing** facilities from `pkg/log` and `pkg/trace`.

## Deployment Diagram
```
+-------------------+       +-------------------+       +-------------------+
|  Kubernetes      |       |  Service Mesh     |       |  A2A Agents       |
|  (Ingress)       | <---> |  Envoy/istio      | <---> |  (adk-go)         |
+-------------------+       +-------------------+       +-------------------+
        |                              |
        v                              v
   A2A Server (pkg/a2a) ----> AegisGate Core (pkg/mcp)
```
- The A2A Server runs as a side‑car or independent service.
- All guardrails are enforced before any request reaches the core business logic.

## Future Extensibility
- **Plug‑in Guardrails** – New guardrails can be added by implementing the corresponding interface and inserting it into the middleware chain.
- **Policy Engine** – Replace static checks with a policy language (OPA) for dynamic guardrail decisions.
- **Observability** – Export detailed per‑guardrail audit logs to Loki/EFK stack.

## Open Design Decisions
1. **AuthProvider choice** – Mutual TLS is default; JWT fallback will be added in Sprint 8.
2. **Rate limit granularity** – Currently per‑agent; may evolve to per‑IP or per‑tenant.
3. **Schema storage** – JSON schemas are embedded at compile‑time; we may move to external schema registry.

---
*Document generated on $(date)*
