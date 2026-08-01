# Federated IOC Library

> **Status:** Shipped in AegisGate v3.6.0+ (Track 6 Task 3+4).
> **Audience:** AegisGate operators, SREs, and security architects.
> **Scope:** Architecture, operator guide, threat model, wire format.

## Introduction

The Federated IOC (Indicator of Compromise) library is the
network-effect moat of the AegisGate platform. Every AegisGate
instance produces hash-fingerprinted IOCs from local detections,
signs attestations over them, and (opt-in) exchanges signed
bundles with peer instances over a pull-based HTTP gossip
protocol.

The library is **hash-based, not ML**. A SHA-256 fingerprint over
a canonicalized detection event is the IOC identifier. No
transformer, embedding model, or other machine-learned component
is introduced in the binary. The fingerprint is stable,
privacy-preserving (no raw payload in the input), and identical
for two instances that saw the same logical event.

The library is **opt-in, serverless, and tier-gated**:

- **Opt-in**: every instance is configured with two flags,
  `AEGISGATE_IOC_SHARE` (serve bundles) and
  `AEGISGATE_IOC_RECEIVE` (fetch peer bundles). Both default to
  off.
- **Serverless**: there is no central server, no coordinator, no
  shared registry. The gossip protocol is pull-based HTTP;
  every instance is both a server and a client.
- **Tier-gated**: any tier can **send** IOCs; only
  **Professional+** instances can **receive** IOCs from peers.
  The tier gate is enforced locally per-instance with no shared
  state (the same way the compliance manifest tier gate works).

## High-Level Architecture

```
+-------------------------+         +-------------------------+
|   AegisGate Instance A  |         |   AegisGate Instance B  |
|   (e.g. developer tier) |         |   (e.g. professional)   |
+-------------------------+         +-------------------------+
         |                                       |
         |  logging.Record(Event)                |
         v                                       v
+-------------------------+         +-------------------------+
|   logging.Recorder      |         |   logging.Recorder      |
|   (pkg/logging)         |         |   (pkg/logging)         |
+-------------------------+         +-------------------------+
         |                                       |
         v                                       v
+-------------------------+         +-------------------------+
|   IOC Producer          |         |   IOC Producer          |
|   (pkg/ioc/producer.go) |         |   (pkg/ioc/producer.go) |
+-------------------------+         +-------------------------+
   |  allow-list filter             |  allow-list filter
   |  (proxy_response,              |  (proxy_response,
   |   anomaly_score,               |   anomaly_score,
   |   response_*)                  |   response_*)
   v                                v
+-------------------------+         +-------------------------+
|   IOC Store             |         |   IOC Store             |
|   (pkg/ioc/store.go)    |         |   (pkg/ioc/store.go)    |
|                         |         |                         |
|   keyed by SHA-256      |         |   keyed by SHA-256      |
|   fingerprint           |         |   fingerprint           |
+-------------------------+         +-------------------------+
         |                                       |
         |   /api/v1/ioc/manifest               |
         |   (signed Bundle)                     |
         |<--------------------------------------+
         |                                       |
         v                                       v
+-------------------------+         +-------------------------+
|   Verify ECDSA P-256    |         |   Verify ECDSA P-256    |
|   (pkg/ioc/attest.go)   |         |   (pkg/ioc/attest.go)   |
+-------------------------+         +-------------------------+
         |                                       |
         v                                       v
   Receiver.Ingest()                         Receiver.Ingest()
   (merge into local store)                  (merge into local store)
```

The producer subscribes to the global `logging.Recorder` (the
same primitive used by the audit ring buffer and the proxy
recorder middleware). It filters events through an allow-list,
computes a SHA-256 fingerprint, and writes IOCs into the local
store. The store is the source of truth for what this instance
has observed.

A second component (the Sync) serves the local store as a
signed Bundle on `GET /api/v1/ioc/manifest` and fetches peer
bundles on a 5-minute timer. Every bundle and every
IOCAttestation inside it is signed with ECDSA P-256; any third
party can verify with no out-of-band key exchange.

## Core Components

| Component | Responsibility | Key Files |
|-----------|----------------|-----------|
| **`types.go`** | Public types: `IOC`, `IOCType`, `Severity`, `IOCAttestation`, `Bundle` | `pkg/ioc/types.go` |
| **`fingerprint.go`** | SHA-256 over canonicalized `Detection` | `pkg/ioc/fingerprint.go` |
| **`attest.go`** | `SignAttestation` / `VerifyAttestation` (ECDSA P-256, SEC 1 pub key) | `pkg/ioc/attest.go` |
| **`bundle.go`** | `Bundle.Sign` / `VerifyBundleSignature` / `VerifyAll` | `pkg/ioc/bundle.go` |
| **`store.go`** | In-memory + disk-backed IOC store, `Observe`, `Snapshot`, `Prune`, `RunFlusher` | `pkg/ioc/store.go` |
| **`producer.go`** | `logging.Record()` subscriber with allow-list filter | `pkg/ioc/producer.go` |
| **`sync.go`** | HTTP handler (`/manifest`, `/health`), `FetchPeer`, `Receiver.Ingest`, `CanReceive` | `pkg/ioc/sync.go` |

## Cryptography

The library uses **ECDSA P-256** for all signing operations. This
matches the existing compliance manifest signer and is the
platform-wide default. The signing key is persisted in
`${DataDir}/ioc/key.json` (PEM-encoded SEC 1 / "EC PRIVATE
KEY") and survives process restarts so signed bundles are still
verifiable across restarts.

The on-disk format for the key is base64 JSON wrapping the PEM
private key plus the base64(SEC 1) public key. A future
iteration may switch to envelope-encrypted KMS-backed keys; the
current implementation is suitable for on-premise deployments
where `${DataDir}` is on an encrypted filesystem.

The signature envelope on the wire is identical to the
compliance manifest format proven in
`testlab/cross_instance_lab_test.go`:

```json
{
  "algorithm": "ecdsa-p256",
  "keyId": "ioc-XXXXXXXX",
  "value": "<base64 ASN.1(r, s)>"
}
```

The public key envelope is:

```json
{
  "algorithm": "ecdsa-p256",
  "keyId": "ioc-XXXXXXXX",
  "value": "<base64 SEC 1 uncompressed, 65 bytes>"
}
```

This is the same shape used in compliance manifests, which means
a single verifier (in main.go or in a customer-side library) can
verify both artifact types.

## Wire Format: Bundle

A Bundle is a signed collection of IOCAttestations:

```json
{
  "bundleId": "<uuid v4>",
  "instanceId": "<opaque instance id, 32 hex chars>",
  "issuedAt": "2026-06-15T08:00:00Z",
  "count": 42,
  "attestations": [
    {
      "fingerprint": "<hex sha256, 64 chars>",
      "instanceId": "abc123def456...",
      "iocType": "proxy_response",
      "severity": "high",
      "firstSeen": "2026-06-15T07:00:00Z",
      "lastSeen": "2026-06-15T08:00:00Z",
      "count": 5,
      "publicKey": { "algorithm": "ecdsa-p256", "keyId": "ioc-XXXX", "value": "..." },
      "signature":  { "algorithm": "ecdsa-p256", "keyId": "ioc-XXXX", "value": "..." }
    }
  ],
  "publicKey": { "algorithm": "ecdsa-p256", "keyId": "ioc-XXXX", "value": "..." },
  "signature":  { "algorithm": "ecdsa-p256", "keyId": "ioc-XXXX", "value": "..." }
}
```

The signature on the bundle covers the canonicalized JSON of
the bundle MINUS the `signature` field. Each IOCAttestation is
also signed individually, so a client can verify a single
attestation without re-verifying the entire bundle.

## HTTP Endpoints

Every AegisGate instance that has `--ioc-share` enabled serves:

| Endpoint | Description | Response |
|----------|-------------|----------|
| `GET /api/v1/ioc/manifest` | Signed Bundle of all locally-known IOCs | 200 / 403 |
| `GET /api/v1/ioc/manifest?since=<rfc3339>` | Signed Bundle of IOCs with `LastSeen >= since` (delta sync) | 200 / 400 / 403 |
| `GET /api/v1/ioc/health` | Service health check | 200 / 503 |

`--ioc-share` is the gate for all three. If disabled, the
manifest endpoints return 403 and the health endpoint returns
503. The handler is mounted unconditionally so the health
endpoint can report the current state (healthy / disabled).

## Operator Guide

### Enabling IOC Sharing

Set the environment variables (or pass the corresponding CLI
flags) and restart the platform:

```bash
# Serve IOCs to peers. Any tier can share.
export AEGISGATE_IOC_SHARE=true

# Receive IOCs from peers. Requires Professional+ tier.
export AEGISGATE_IOC_RECEIVE=true

# Comma-separated peer base URLs.
export AEGISGATE_IOC_PEERS="https://aegis-b.example.com:8443,https://aegis-c.example.com:8443"

# Or via CLI flags:
#   --ioc-share --ioc-receive --ioc-peers=https://...
```

The platform logs the resolved configuration at startup:

```
Federated IOC: instance_id=abc123def456..., share=true, receive=true, peers=2, store=/data/ioc
Federated IOC: handler mounted at /api/v1/ioc/
```

### Verifying the Health Endpoint

```bash
curl -s https://aegis.example.com:8443/api/v1/ioc/health | jq
```

Healthy response:

```json
{
  "status": "healthy",
  "instanceId": "abc123def456...",
  "iocCount": 42
}
```

Disabled response (HTTP 503):

```json
{
  "status": "disabled",
  "reason": "share not enabled"
}
```

### Pulling a Manifest

```bash
# Full manifest
curl -s https://aegis.example.com:8443/api/v1/ioc/manifest | jq

# Delta since a timestamp
curl -s "https://aegis.example.com:8443/api/v1/ioc/manifest?since=2026-06-15T00:00:00Z" | jq
```

### Verifying a Manifest (Customer-Side)

A customer can verify a manifest they pulled from an AegisGate
instance with no out-of-band key exchange. The public key is
embedded in the bundle. The verification path is:

1. Parse the JSON.
2. Compute the bundle payload (the JSON with the `signature`
   field zeroed).
3. SHA-256 the payload.
4. ECDSA-verify the signature against the embedded public key.
5. For each IOCAttestation in `attestations`, repeat steps 2-4.

`pkg/ioc/attest.go` exports `VerifyAttestation` and
`pkg/ioc/bundle.go` exports `VerifyBundleSignature` and
`Bundle.VerifyAll`. These are the same functions used by
AegisGate internally to verify peer bundles.

### Inspecting the Local Store

The local store is persisted at `${DataDir}/ioc/store.json`.
The on-disk format is a single JSON array of IOC records:

```bash
cat /data/ioc/store.json | jq '.[0:3]'
```

```json
[
  {
    "fingerprint": "5a7d...",
    "type": "proxy_response",
    "severity": "high",
    "firstSeen": "2026-06-15T08:00:00Z",
    "lastSeen": "2026-06-15T09:00:00Z",
    "count": 5,
    "source": "proxy"
  }
]
```

The store is flushed atomically (write to temp + rename) on a
30-second timer; a crash mid-flush leaves the previous good
state intact.

### Backup and Restore

The IOC data dir contains three files; back them up together:

```bash
# Backup
tar czf ioc-backup-$(date +%Y%m%d).tar.gz /data/ioc/

# Restore (in a stopped platform)
tar xzf ioc-backup-20260615.tar.gz -C /
```

The three files:

| File | Purpose | Sensitivity |
|------|---------|-------------|
| `key.json` | ECDSA P-256 private key | **Confidential** (treat as a credential) |
| `instance-id` | Opaque instance identifier (32 hex chars) | Public |
| `store.json` | Locally-observed IOCs | Public (no PII; fingerprint + minimal metadata) |

The `key.json` file is the most sensitive: anyone with the key
can sign bundles in this instance's name. Restrict file
permissions (`0600`, owner read/write only).

## Threat Model

### What the IOC library protects against

- **Detection evasion by adversaries**: when AegisGate
  Instance A blocks a prompt injection from a new payload,
  Instance B can pull the IOC from A's manifest and add it
  to its own store, blocking the same payload without
  re-observing it.

- **Slow-and-low attacks across many instances**: the count
  field on each IOC aggregates observations from all
  instances that have shared the bundle. A high count on a
  peer instance is a strong signal that an IOC is
  widespread.

- **Compliance evidence corruption**: every bundle and every
  attestation is signed; a tampered IOC fails verification
  and is dropped.

### What the IOC library does NOT protect against

- **Adversaries with the private key**: if an attacker
  obtains the key in `key.json`, they can sign bundles in
  this instance's name. The library does not have key
  rotation yet; a future iteration will add it.

- **Insider attacks on a single instance**: the library
  trusts the producer (the local producer is the
  source-of-truth for IOCs). If the local producer is
  compromised, the IOCs it writes are trusted. This is the
  same trust model as the rest of the platform: the platform
  trusts the local process.

- **Privacy leaks via the fingerprint**: the fingerprint is
  computed over the `Detection` struct, which is
  deliberately a subset of `logging.Event` (no source IP,
  user, client ID, request body, response body, or any other
  identifying field). An attacker with the fingerprint
  cannot recover the underlying payload. They CAN tell
  whether two IOCs are the same (via the fingerprint), which
  is the intended behavior.

- **Sybil attacks (a peer feeding bad IOCs)**: the bundle
  signature authenticates the source, but it does not
  authenticate the *truth* of the IOCs inside. A peer can
  sign a bundle of fake IOCs and distribute it. The library
  is built to be combined with reputation: in v3.6.0 the
  client trusts the peer's bundle signature; a future
  iteration will add peer reputation and per-source IOC
  weight (e.g., downweight IOCs from a peer with a high
  fake-IOC rate).

### What is and is not shared

The `Detection` struct (fingerprint.go) is the privacy
boundary. It contains only:

- `Type` (e.g., "proxy_response", "anomaly_score")
- `Severity` (e.g., "high", "critical")
- `Pattern` (e.g., "secret_aws_access_key", "pii_ssn_us")
- `ThreatType` (e.g., "credential_exposure")
- `ThreatLevel` (e.g., "active", "potential")
- `ComplianceFramework` (e.g., "GDPR", "HIPAA")
- `ComplianceControl` (e.g., "Art.32", "164.312(a)(1)")

It does **NOT** contain:

- Source IP, source hostname, or any other network identifier
- User, client ID, or any other account identifier
- Request body, response body, or any other payload data
- Customer name, license ID, or any other commercial identifier

The IOC record itself adds only the SHA-256 fingerprint and
minimal metadata (first-seen, last-seen, count, source).
Nothing in the record can be used to attribute a detection to
a specific customer or environment.

## Testing

### Unit tests

```bash
go test ./pkg/ioc/...
```

74 tests, 84.1% coverage. Covers all primitives and the major
error paths.

### Lab tests

```bash
# The four in-process lab tests (gossip round-trip, tier
# gate, delta query, plus the smoke test) live in
# testlab/cross_instance_ioc_lab_test.go. They require
# the `lab` build tag and (for the smoke test) the
# testlab docker stack.
LAB_ENABLED=1 go test -tags=lab -run TestLabIOC ./testlab/...
```

The gossip round-trip, tier gate, and delta query tests use
local httptest servers and do not require the testlab stack.
The smoke test (`TestLabIOC_Setup_VerifyBothInstancesReachable`)
checks that the two testlab instances are reachable; it requires
`cd testlab && docker compose up -d`.

### Full lab suite

```bash
bash scripts/run-lab-tests.sh
```

This runs posture, evidence, logging, and ioc lab tests in
sequence. The IOC package is now in the default `LAB_PACKAGES`
list (alongside posture, evidence, and logging).

## Operational Notes

### Gossip Interval

The receiver runs a 5-minute ticker (`pkg/ioc/sync.go`,
`RunReceiver`). Each tick, the instance fetches the manifest
from every configured peer. The interval is hard-coded in
v3.6.0; a future iteration will make it configurable.

### Store Capacity and Eviction

The default in-memory capacity is 100,000 IOCs
(`DefaultStoreCapacity` in `pkg/ioc/store.go`). When the cap
is hit, the IOC with the oldest `LastSeen` is evicted. This
biases the store toward recent IOCs, which are the most
operationally useful. A 30-day max age is applied on every
flush (`DefaultMaxAge`).

### Performance

The producer's hot path (an event that does NOT pass the
allow-list, which is the common case for most events) is:

1. One atomic load (`enabled.Load()`).
2. One map lookup in the allow-list.
3. One method call to the inner recorder.

There is no allocation, no hashing, no signing. The cost is on
the order of 10ns per event.

For an event that DOES pass the allow-list, the cost is:

1. SHA-256 over a small canonicalized struct (a few hundred
   bytes) — about 1µs.
2. Map lookup in the store (RWMutex under read lock).
3. IOC allocation + write — about 100ns.

The cost is on the order of 2µs per IOC, dominated by the
SHA-256. This is acceptable for the production event rate
(observed 3-10 events/second on a typical AegisGate
deployment).

## See Also

- `pkg/ioc/ioc_test.go` and `pkg/ioc/ioc_coverage_test.go`:
  74 unit tests, 84.1% coverage
- `testlab/cross_instance_ioc_lab_test.go`: 4 lab tests
  proving gossip, tier gate, and delta query
- `testlab/cross_instance_lab_test.go`: the cross-instance
  compliance manifest test that the IOC library is patterned
  after
- `docs/a2a-security-middleware-design.md`: the design doc
  for the A2A middleware; the IOC library's HTTP handler
  follows the same patterns
- `SESSION-ANCHOR-2026-06-14-track-1-6-complete.md`: the
  session summary for Track 1-6
- `pkg/logging/recorder.go`: the global event recording
  primitive that the IOC producer subscribes to
