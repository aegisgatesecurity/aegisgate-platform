# AegisGate Federated IOC Library (Customer 1-pager)

**Status:** v3.5.0+ (Track 6 Task 3+4, shipped)  
**Last reviewed:** 2026-07-21  
**Audience:** AegisGate customers evaluating threat intelligence value, security architects, MSSP partners, and AegisGate sales engineers answering "what does 'federated' mean and why should I care?" questions.

This document is a 1-page customer explainer. The full technical architecture (architecture, operator guide, threat model, wire format) lives at `docs/federated-ioc-library.md` (the operator/architect doc). This 1-pager focuses on the **business value** for customers evaluating AegisGate.

---

## The Value Proposition (1 sentence)

**1 customer's threat = all AegisGate customers protected.** The federated IOC library turns every AegisGate instance into a real-time threat intelligence feed for every other AegisGate instance — without a central server, without ML models, and without your data leaving your network without your consent.

## Why this matters

Every security team knows the same truth: **threats move faster than any single team's detection capability**. A new prompt-injection technique, a new API-key-leaking tool call, a new exfiltration pattern — by the time your SOC sees it in the wild, the attack has already happened.

Traditional threat intelligence vendors solve this with a **central server** that aggregates indicators from paid feeds (CrowdStrike, Mandiant, Recorded Future) and ships them to your SIEM. Problems with this model:

- **Cost**: $50K–$500K/year per vendor, on top of your SIEM license
- **Latency**: minutes to hours from indicator observation to your perimeter
- **Coverage gap**: paid feeds don't see AI-specific attacks (prompt injection, MCP abuse, RAG poisoning) because those vendors don't operate in the AI security space
- **Privacy**: your detection events leave your network to reach the central server

The AegisGate Federated IOC Library solves all four problems. **Every AegisGate instance is both a producer and a consumer of IOCs.** When Customer A's AegisGate instance detects a new prompt-injection campaign, Customer B's instance sees the IOC within minutes — with no central server, no paid feed, and no egress of raw payloads.

## How it works (the 30-second version)

1. **Local detection** — AegisGate's scanner detects an attack pattern (PII exfiltration, prompt injection, etc.)
2. **Hash fingerprinting** — AegisGate computes a SHA-256 fingerprint over the canonicalized detection event. The fingerprint is the IOC identifier. Raw payload never leaves the network.
3. **Local signing** — AegisGate signs an `IOCAttestation` with its ECDSA P-256 key, declaring "instance X saw this IOC at this severity at this time." Signature is over the canonicalized attestation JSON.
4. **Bundle creation** — AegisGate bundles multiple attestations into a signed `Bundle` (also ECDSA-signed, same primitives as the Trust Framework's envelopes).
5. **Gossip** — AegisGate periodically pulls signed bundles from peer instances (configured peer list, or any AegisGate instance reachable on the network). Each bundle is verified against the embedded public key before the IOCs are added to the local store.
6. **Local enforcement** — New IOCs are added to the local IOC store. The next incoming request that matches a known IOC is blocked (or audited, per tier config) before it reaches the LLM.

## The 4 design principles

1. **Hash-based, not ML.** A SHA-256 fingerprint over a canonicalized detection event is the IOC identifier. No transformer, no embedding model, no ML-based fuzzy matching. The fingerprint is **deterministic, stable, and privacy-preserving** — two instances that saw the same logical event produce the same fingerprint, with no raw payload in the input.
2. **Opt-in, serverless, tier-gated.**
   - **Opt-in**: every instance is configured with two flags, `AEGISGATE_IOC_SHARE` (serve bundles) and `AEGISGATE_IOC_RECEIVE` (fetch peer bundles). Both default to **off**. You choose whether to share and whether to receive.
   - **Serverless**: there is no central server, no coordinator, no shared registry. The gossip protocol is pull-based HTTP; every instance is both a server and a client. The protocol survives any single instance going offline.
   - **Tier-gated**: any tier can **send** IOCs; only **Professional+** instances can **receive** IOCs from peers. The tier gate is enforced locally per-instance with no shared infrastructure.
3. **Self-verifying.** Every bundle includes the producer's public key and signature. The consumer verifies the signature before adding IOCs to its local store. No PKI, no certificate authority, no central trust anchor — the producer's public key IS the trust anchor, and it's embedded in the bundle.
4. **Privacy-first.** Raw payloads never leave the producing instance. Only canonicalized detection events (with PII fields redacted by default, per `pkg/response/pii_scanner.go`) are signed and shared. A customer can audit the bundle format at any time to verify.

## What's enforced vs. recommended

- **Enforced by AegisGate at runtime** (when `AEGISGATE_IOC_RECEIVE=true`):
  - Every incoming request is checked against the local IOC store before it reaches the LLM
  - A match produces a `severity=high` compliance event
  - Configurable action: BLOCK (default for Professional+ tier), AUDIT_ONLY (Community/Developer tier)
- **Recommended for threat intelligence program** (when `AEGISGATE_IOC_SHARE=true`):
  - Your AegisGate instance shares your local detections with peer instances
  - Recommended for organizations with mature threat intelligence programs
  - The CISO Posture Digest (`pkg/digest/`) includes a "threats detected and shared" section

## Customer-facing API

The IOC store exposes a customer HTTP API at `/api/v1/ioc/admin/`:

| Endpoint | What it returns | Auth |
|----------|-----------------|------|
| `GET /api/v1/ioc/admin/list?since=TS&severity=high` | List IOCs in the local store | License (Professional+) |
| `GET /api/v1/ioc/admin/stats` | IOC store statistics (count by severity, by IOC type) | License (Professional+) |
| `POST /api/v1/ioc/admin/import` | Import a STIX 2.1 bundle (TAXII 2.1 import) | License (Professional+) |
| `POST /api/v1/ioc/admin/export` | Export a STIX 2.1 bundle (TAXII 2.1 export) | License (Professional+) |
| `GET /api/v1/ioc/admin/bundle?since=TS` | Download a signed AegisGate bundle | License (Professional+) |
| `GET /api/v1/ioc/admin/peers` | List configured peer instances | License (Professional+) |

The TAXII 2.1 import/export is the **bridge to your existing threat intelligence stack** — you can pull IOCs from your paid feeds into AegisGate, and push AegisGate-generated IOCs to your SIEM.

## Tier & pricing

- **Tier required:** Professional+ for `AEGISGATE_IOC_RECEIVE=true` (gossip consumer)
- **All tiers can send IOCs** (`AEGISGATE_IOC_SHARE=true`) — there's no charge to contribute to the network
- **Storage:**
  - Community: 7-day retention
  - Developer: 30-day retention
  - Professional: 90-day retention
  - Enterprise: unlimited
- **No separate "IOC module" pricing.** The federated library is part of the tier.

## Concrete customer example (anonymized)

> A regulated-industry customer deploys AegisGate Professional across 8 internal LLM applications. On a Tuesday afternoon, their customer-support agent receives a sophisticated prompt-injection attempt that bypasses their existing email security and DLP. AegisGate's scanner detects the pattern, computes the IOC fingerprint, signs the attestation, and adds it to the local store.
>
> Within 17 minutes (next gossip pull), AegisGate instances at 6 other AegisGate Professional customers see the same IOC. By Wednesday morning, **the IOC has been seen and blocked at 4 of those 6 customers' instances** before any of them encountered the attack in the wild.
>
> Without the federated library, each of those 6 customers would have had to wait until the attack reached them — a 24–72 hour window during which the attack was live in their environment.

This is the **network effect** that makes AegisGate more valuable as more customers join. It is the same model as Crowdstrike Falcon's threat graph, but applied to **AI-specific threats** and gated to **opt-in Professional+ customers only**.

## What AegisGate does NOT cover (out of scope)

- **Central coordinator.** There is no AegisGate-operated central server. The network is fully peer-to-peer. If you want a managed threat feed, you can run your own coordinator instance and configure it as a peer.
- **Cross-organization identity.** The federated library uses ECDSA public keys as identity. There is no central PKI. Cross-org trust federation (e.g. "Company A's instances trust Company B's signatures because both are signed by a known CA") is on the v4.0+ roadmap.
- **ML-based IOC matching.** The library is hash-based. Fuzzy matching (e.g. "this new prompt injection is 85% similar to a known IOC") is on the v4.x ML tier roadmap.
- **Real-time push.** The protocol is pull-based (HTTP GET). Push-based delivery (webhooks, message queues) is a v4.0+ feature for the high-trust Enterprise tier.
- **Encrypted bundles.** Bundles are signed but not encrypted. The IOC content is public-by-design (anyone can verify the signature and see the IOC). If you need to share sensitive IOCs, use the bundle's `metadata.private` flag and a private peer list.

## Linkage to other AegisGate modules

- **Trust Framework + IOC library**: a sudden spike in IOC matches for an agent causes the trust score to drop faster. The Trust Framework's behavioral anomaly detection and the IOC library's signature-based detection are **complementary signals**.
- **Compliance modules (HIPAA, SOC 2, EU AI Act)**: each compliance scan report can include the IOC context — "this control failed because the request matched IOC `sha256:abc...` which is on the customer's threat watch list."
- **AegisGate Lens (browser extension)**: when a Lens user encounters a new prompt-injection pattern, the IOC is generated and (if `AEGISGATE_IOC_SHARE=true`) shared with the federated library. Browser-side detection becomes server-side protection for all AegisGate customers.

## Versioning

| AegisGate version | Federated IOC status |
|-------------------|----------------------|
| v3.0.0 and earlier | Local IOC store only, no federation |
| v3.2.0 | IOC store introduced (pkg/ioc/, in-memory + PostgreSQL) |
| v3.3.0 | ECDSA-signed IOCAttestation + Bundle wire format |
| v3.5.0+ | Federated gossip protocol, opt-in/opt-out, TAXII 2.1 bridge |
| **v3.5.0+** (current) | **Shipped; production-ready; first production deployment 2026-06-15** |
| v4.0+ (planned) | ML-based fuzzy matching; central coordinator (optional); push delivery |

## References

- Technical architecture: `docs/federated-ioc-library.md` (architecture, operator guide, threat model, wire format)
- IOC store implementation: `pkg/ioc/` (12,902 LOC, includes attest.go, bundle.go, postgres_store.go, taxii_integration.go)
- Threat model: internal document Section 2.7 (federated library STRIDE threats)
- Customer explainer for Trust Framework: `docs/trust-framework.md`
- Customer explainer for EU AI Act: `docs/compliance/eu-ai-act.md`
- Pricing: https://aegisgatesecurity.io/pricing/ (Professional+ tier, no separate IOC module cost)

---

*Document version: 1.0*  
*Last updated: 2026-07-21*  
*AegisGate Platform v3.5.0+*
