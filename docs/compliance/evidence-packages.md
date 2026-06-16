# AegisGate Compliance Evidence Packages

**Status:** Shipped in v3.3.0+ (Track 2, 2026-06-14)
**Audience:** CISOs, compliance officers, customer-facing auditors, security analysts
**First documented:** 2026-06-14

---

## What it is

A **Compliance Evidence Package** is a single, signed JSON artifact that
bundles everything a CISO needs to hand to an auditor for a specific
framework and time window:

- **Per-framework scan result** — control counts, score, per-control
  pass/fail (when available), enforcement reason
- **License snapshot** — tier, modules, customer, expiration (license key
  is NEVER included; only a SHA-256 fingerprint)
- **Audit event anchors** — counts of events by type/severity/framework
  during the period (so the auditor can see this is not a vacuous package)
- **ECDSA P-256 signature** (NIST FIPS 186-4, SEC 1 encoded, ASN.1 DER
  signature) over a SHA-256 hash of the canonical manifest, matching
  the algorithm used by `pkg/trust/attestation`

The package is **independently verifiable**: an auditor with the
manifest JSON and the platform public key can verify it without
re-running any scans, talking to the platform, or trusting the build
pipeline. That is the trust contract.

---

## Why this is differentiated

No other AI security platform ships a signed, auditor-ready evidence
package. Competitors (Lakera, NeMo Guardrails, Rebuff, Protect AI) all
produce *scans* — counts, scores, lists. None of them produce an
*artifact* a CISO can hand to an external auditor and have it
verified independently.

The AegisGate evidence package is the only one that:

1. Is cryptographically signed (not just a JSON dump)
2. Cross-references the platform's compliance scan output
3. Includes the customer license fingerprint (so the auditor can
   correlate back to the customer record without exposing the key)
4. Anchors to the platform's audit log (so "no activity" packages
   are visible as "no activity" rather than "missing data")
5. Is independently verifiable (the auditor only needs the JSON + a
   public key — no callback to the platform, no network)

For EU enterprise, HIPAA, SOC 2, and PCI customers, this is the
difference between "we run AegisGate" and "we run AegisGate AND we
can prove it to our auditor in 5 minutes."

---

## CLI usage

### Build an evidence package

```
$ aegisgate evidence build --framework=hipaa --start=2026-04-01 --end=2026-06-30
Built evidence manifest: cli-8b1e2bdda0f72190
  Framework: hipaa
  Period:    2026-04-01 -> 2026-06-30
  Stored at: ./var/evidence/evidence.jsonl
  Key ID:    cli-810dd80088d1
  
  Full manifest:
  { ... }
```

### List stored manifests

```
$ aegisgate evidence list --limit=10
Found 1 manifest(s) in ./var/evidence/evidence.jsonl:
  OK      cli-8b1e2bdda0f72190  hipaa         2026-04-01 -> 2026-06-30
```

The `OK` / `INVALID` prefix on each row is the live signature
verification status. `INVALID` means the stored manifest has been
tampered with (or was signed by a key that no longer exists).

### Verify a manifest

```
$ aegisgate evidence verify --store-dir=./var/evidence cli-8b1e2bdda0f72190
VERIFIED cli-8b1e2bdda0f72190 (key=cli-810dd80088d1, signed_at=2026-06-14T23:04:00Z)
```

Exit code is 0 on verification success, 1 on failure. Suitable for
CI gates:

```bash
if ! aegisgate evidence verify <id> >/dev/null 2>&1; then
    echo "Evidence manifest INVALID - do not release to customer"
    exit 1
fi
```

### JSON output

All subcommands accept `--json` for machine-readable output:

```
$ aegisgate evidence verify <id> --json
{
  "verified": true,
  "manifest_id": "cli-8b1e2bdda0f72190",
  "key_id": "cli-810dd80088d1",
  "signed_at": "2026-06-14T23:04:00Z"
}
```

---

## HTTP API

The same operations are available over HTTP for platform integrations:

| Route | Method | Purpose |
|-------|--------|---------|
| `/api/v1/compliance/evidence/build` | POST | Build a new manifest |
| `/api/v1/compliance/evidence/list` | GET | List stored manifests (summary) |
| `/api/v1/compliance/evidence/:id` | GET | Get a specific manifest |
| `/api/v1/compliance/evidence/:id/verify` | GET | Verify a specific manifest |

### Build a manifest (HTTP)

```bash
curl -X POST https://aegisgate.example.com:8443/api/v1/compliance/evidence/build \
  -H "Authorization: Bearer $AEGISGATE_LICENSE_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "framework": "eu_ai_act",
    "period_start": "2026-04-01T00:00:00Z",
    "period_end": "2026-06-30T23:59:59Z"
  }'
```

Response: the full signed Manifest (201 Created).

### Verify a manifest (HTTP)

```bash
curl https://aegisgate.example.com:8443/api/v1/compliance/evidence/<id>/verify
```

Response:

```json
{
  "verified": true,
  "manifest_id": "..."
  "key_id": "..."
  "signed_at": "..."
}
```

Note: `/verify` returns 200 OK with `verified: false` when the signature
is invalid, so HTTP clients can read the body without treating it as
a transport error.

---

## Independent verification (auditor workflow)

An external auditor does NOT need the platform, the binary, or any
network access. They need:

1. The signed manifest JSON (e.g., `evp_2026Q3_abc123.json`)
2. The platform public key (e.g., from
   `https://aegisgatesecurity.io/.well-known/aegisgate-evidence-pubkey.pem`)

Verification is then a 10-line Go program:

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "github.com/aegisgatesecurity/aegisgate-platform/pkg/evidence"
)

func main() {
    data, _ := os.ReadFile(os.Args[1])
    var m evidence.Manifest
    json.Unmarshal(data, &m)
    if err := evidence.Verify(&m); err != nil {
        fmt.Printf("INVALID: %v\n", err)
        os.Exit(1)
    }
    fmt.Println("VERIFIED")
}
```

Or via the `aegisgate evidence verify` CLI subcommand if the auditor
is willing to install the binary:

```
$ aegisgate evidence verify --store-dir=/path/to/store <manifest-id>
VERIFIED ...
```

---

## Storage format

Manifests are stored as **JSONL** (one JSON object per line) in
`./var/evidence/evidence.jsonl` (overridable via `--store-dir` or
`AEGISGATE_DATA_DIR`). JSONL is:

- **Append-only** (the Store uses O_APPEND, no in-place mutation)
- **Greppable** (each line is a self-contained JSON object)
- **Email-friendly** (the file can be split into lines and emailed
  to an auditor one manifest at a time)
- **Backup-friendly** (a `cp` of the file is a complete backup)

The store does NOT use SQLite, PostgreSQL, or any other database.
v0.1 scope is "dozen manifests per customer per year" — JSONL is
the right tool. A future v0.2 can add a sidecar index for O(1)
lookup if the count grows.

---

## Manifest schema (for auditors)

The top-level fields of a Manifest:

| Field | Type | Meaning |
|-------|------|---------|
| `manifest_id` | string | UUID, unique per package |
| `framework` | string | Canonical name (`hipaa`, `pci`, `eu_ai_act`, ...) |
| `framework_version` | string | Framework spec version (best-effort) |
| `period.start` / `period.end` | RFC3339 | Time window this package covers |
| `license.fingerprint` | hex | SHA-256 of the license key (auditor correlation) |
| `license.tier` | string | License tier at time of build |
| `license.customer` | string | Customer name from license payload |
| `license.expires_at` | RFC3339 | License expiration |
| `license.modules_owned` | []string | Compliance modules owned |
| `license.valid` | bool | License was valid at build time |
| `generated_at` | RFC3339 | When the package was built |
| `builder_version` | string | AegisGate version that built it |
| `framework_evidence.enforced` | bool | Framework was enforced for this license |
| `framework_evidence.score` | float | Compliance score 0-100 |
| `framework_evidence.controls_total` | int | Number of controls in framework |
| `framework_evidence.controls_enforced` | int | Number that pass |
| `framework_evidence.compliance_pct` | float | controls_enforced / controls_total * 100 |
| `framework_evidence.reason_enforced` / `reason_not_enforced` | string | Why |
| `audit_anchors.event_count` | int | Total audit events in the period |
| `audit_anchors.by_type` | map | Counts by event type |
| `audit_anchors.by_severity` | map | Counts by severity |
| `audit_anchors.by_framework` | map | Counts by compliance framework |
| `audit_anchors.source` | string | "ring_buffer" or "unavailable" |
| `signature.algorithm` | string | Always "ecdsa-p256" |
| `signature.key_id` | string | Opaque key identifier |
| `signature.value` | []byte | ASN.1 DER signature |
| `signature.public_key` | []byte | SEC 1 encoded public key |
| `signature.signed_at` | RFC3339 | When the signature was generated |

The signature is over a SHA-256 hash of the **canonical JSON** of
the manifest with the `signature` field zeroed. Canonicalization uses
`encoding/json` default settings, which sorts map keys alphabetically.

---

## Design notes

### Why ECDSA P-256 (and not Ed25519)?

The platform already uses ECDSA P-256 for the trust attestation
subsystem (`pkg/trust/attestation`). The evidence package reuses the
same algorithm + SEC 1 encoding for consistency. A future v3.4.0+
release plans to migrate to `crypto/ecdh` (per the comment in
`pkg/trust/attestation/generator.go:53`); when that lands, the
evidence package will migrate with it.

### Why JSONL (and not SQLite)?

Simplicity. The founder needs to be able to `cat` the store, grep
it, and email a single line to an auditor. SQLite would add a
dependency, a migration story, and operational complexity for no
benefit at the "dozen manifests per year" workload.

### Why no per-control details (yet)?

The platform's compliance scan engine (v3.2.0 Phase 3) currently
exposes AGGREGATE per-framework data: total controls, enforced
controls, score, reason. Per-control pass/fail is a v3.4.0+
addition. When that ships, the evidence package will pick it up
automatically (the `FrameworkEvidence.Assessment` field already
exists; it is just left nil until per-control data is available).

### Why is the CLI signing key ephemeral?

v0.1 of the CLI generates a fresh ECDSA P-256 key for each
invocation. This means CLI-built manifests cannot be verified after
the CLI process exits. That is acceptable for the founder's
immediate use case (build a manifest, email it to the auditor, done).
Production deployments use the platform binary, which signs with the
persisted trust keystore (`pkg/trust/identity/keystore.go`).

---

## Related

- **Posture check** (`aegisgate status`) — the operator-level "is your
  AegisGate doing what you think it is doing?" signal. Pair it with
  the evidence package: posture says "the platform is healthy" and
  the evidence package says "and here is the auditor-ready proof."
- **Compliance scan engine** (`GET /api/v1/compliance/scan`) —
  underlying source of the per-framework scores in the evidence
  package.
- **Trust Framework** (`GET /api/v1/trust/attestations`) —
  per-session signed attestations (different artifact, different
  granularity).
- **V3.3.0-ROADMAP §6.5** — the posture check spec (the sister deliverable).

---

*Shipped in v3.3.0+ (Track 2, 2026-06-14). Documented 2026-06-14.*