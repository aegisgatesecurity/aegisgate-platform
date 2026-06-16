# pkg/attestation — AegisGate Signed Attestation Envelope

**Status:** Tier 5 prep, frozen 2026-06-15d
**Version:** v3.5.0-alpha-1 target
**Council of Mine:** 8/8 unanimous Devil's Advocate on 2/2 non-obvious choices

The `pkg/attestation/` package is the AegisGate signed-attestation
envelope primitive. It wraps any domain-specific payload
(evidence manifest, evaluation result, AIBOM, agent intent,
prompt cache attestation, CVE entry) with a tamper-evident,
third-party-verifiable cryptographic binding.

## The envelope

```go
type Envelope struct {
    ID         string          `json:"id"`                    // UUIDv4
    Type       Type            `json:"type"`                  // e.g., "evidence.manifest.v1"
    IssuedAt   time.Time       `json:"issued_at"`
    ValidUntil time.Time       `json:"valid_until,omitempty"` // zero = no expiration
    Subject    string          `json:"subject"`               // "aegisgate://<kind>/<id>"
    Issuer     string          `json:"issuer"`                // "<instance>:<key>"
    RawPayload json.RawMessage `json:"payload"`               // feature-specific JSON
    Signature  Signature       `json:"signature"`
}

type Signature struct {
    Algorithm string    `json:"algorithm"` // always "ecdsa-p256" in v3.5.0+
    KeyID     string    `json:"key_id"`
    PublicKey []byte    `json:"public_key"` // SEC 1 encoded (65 bytes for P-256)
    Value     []byte    `json:"value"`      // ASN.1 DER signature
    SignedAt  time.Time `json:"signed_at"`
}
```

## The 4 lifecycle operations

```go
// 1. Sign — produce a signed envelope
func Sign(payload []byte, subject string, attType Type, issuer string, kr *ioc.KeyRing, ttl time.Duration) (*Envelope, error)

// 2. Verify — offline, embedded public key
func Verify(env *Envelope) error

// 3. VerifyWithKey — auditor scenario, external public key
func VerifyWithKey(env *Envelope, pub *ecdsa.PublicKey, expectedKeyID string) error

// 4. VerifyOnline — production path, fetch from /.well-known/
func VerifyOnline(ctx context.Context, env *Envelope) error
```

## The 9-reason error taxonomy

| Reason | Retriable? | When |
|---|---|---|
| `ReasonMalformed` | No | envelope is not well-formed JSON |
| `ReasonUnknownType` | No | Type is not in the registry |
| `ReasonInvalidSubject` | No | Subject fails validation |
| `ReasonSignatureInvalid` | **No (CRITICAL)** | signature does not verify |
| `ReasonKeyMismatch` | No | KeyID doesn't match expected |
| `ReasonExpired` | Yes (with skew) | past ValidUntil |
| `ReasonNotYetValid` | Yes (with skew) | IssuedAt in the future |
| `ReasonPublicKeyFetch` | Yes (transient) | /.well-known/ fetch failed |
| `ReasonAlgorithmUnsupported` | No | unsupported algorithm |

## The 7 registered types

| Type | Owner | Purpose |
|---|---|---|
| `evidence.manifest.v1` | `pkg/evidence` | c3 evidence manifest (migrated) |
| `evidence.cross_protocol.v1` | `pkg/evidence` | c1 cross-protocol evidence |
| `evaluator.run.v1` | `pkg/evaluator` | TODO-301 AR-EaaS |
| `aibom.cyclonedx.v1` | `pkg/aibom` | TODO-302 AIBOM |
| `a2a.intent.v1` | `pkg/a2a` | TODO-303 Agent Intent |
| `promptcache.attestation.v1` | `pkg/promptcache` | TODO-304 Prompt Cache |
| `cve.entry.v1` | `pkg/cve` | TODO-305 CVE-for-AI |

## The URI-style subject grammar (Council-adjudicated)

`aegisgate://<kind>/<id>`

Examples:
- `aegisgate://prompt/sha256-abc123...` (TODO-304)
- `aegisgate://deployment/prod-7` (TODO-302)
- `aegisgate://agent/agent-42` (TODO-303)
- `aegisgate://manifest/<uuid>` (c3)
- `aegisgate://ioc/<64-hex>` (Tier 6 Task 3)
- `aegisgate://evaluation/eval-12345` (TODO-301)
- `aegisgate://cve/CVE-2026-12345` (TODO-305)

## The canonicalization (Council-adjudicated)

JCS / RFC 8785, **from-scratch** in `canonical.go` (~200 LOC).
- No vendored JCS library
- ASCII-only string convention
- Validated against the RFC 8785 test vectors (17 test cases in `canonical_test.go`)

## Domain separation

The signed form is `SHA-256("aegisgate-attestation-v1" || canonicalBytes)`.
The `"aegisgate-attestation-v1"` prefix prevents cross-feature
signature replay. To change the envelope format, bump the
prefix to v2 (a wire-incompatible change).

## The c3 migration (v3.5.0+)

c3 evidence manifests gain an optional `Attestation *Envelope` field.
When present, the envelope is the authoritative signature; the
legacy `Signature` field is mirrored for v3.4.0-beta.1 backward
compatibility. Both paths are interchangeable for verification.

```go
// Verify a c3 manifest (v3.4.0-beta.1 legacy path)
if err := evidence.Verify(m); err != nil { ... }

// Verify a c3 manifest (v3.5.0+ envelope path)
if err := evidence.VerifyEnvelope(m); err != nil { ... }
```

## The CLI verb

```bash
# Verify an envelope offline
aegisgate attestation verify envelope.json

# Verify with JSON output
aegisgate attestation verify --json envelope.json

# Verify with expected key ID
aegisgate attestation verify --key-id=key-abc123 envelope.json
```

## The HTTP API (placeholder for v3.5.0-alpha-1)

```
POST /api/v1/attestation/verify
Content-Type: application/json
Body: <envelope JSON>

Returns: 200 OK on success, 400 Bad Request with the
VerificationReason in the body on failure.
```

The endpoint is the auditor's primary interface for online
verification. The implementation is a follow-up to v3.5.0-alpha-1
(the `VerifyOnline` function in `attestation.go` returns
`ReasonPublicKeyFetch` until the `.well-known/` endpoint ships).

## The tier model

The envelope primitive is **not** tier-gated. Every AegisGate
installation can sign and verify envelopes. The 5 platform tiers
(Community, Starter, Developer, Professional, Enterprise) gate
the **KeyRing** (which signing key, whether rotation is allowed,
whether certain types are registrable). The envelope just consumes
the KeyRing.

## Tests

- `canonical_test.go`: 17 RFC 8785 test vectors + 7 edge case tests
- `types_test.go`: 19 tests (registry, kind registration, subject grammar)
- `attestation_test.go`: 36 tests (sign validation, verify, tamper detection, round-trip)

Total: 36 tests, all green under `-race`. 85.4% coverage.

## The design

See `plans/ENVELOPE-DESIGN-v1.1-FROZEN.md` for the full spec.
The design is locked. Any deviation requires a new design-doc
version (v1.2-FROZEN) and user approval.

## The Council

The Council of Mine (9-member LLM council) convened 2026-06-15d
on 2 non-obvious choices:

1. **Canonicalization:** JCS / RFC 8785 vendored vs. from-scratch.
   Council: 8/8 unanimous Devil's Advocate for from-scratch.
   User adopted.

2. **Subject grammar:** single-string `<kind>:<id>` vs. URI-style
   `aegisgate://<kind>/<id>`. Council: 8/8 unanimous Devil's
   Advocate for URI-style. User adopted.

This is the same 8/8 unanimous Devil's Advocate pattern as the
06-15c 3 prior decisions. The user adopts all Council
recommendations after deliberation.

---

**Frozen 2026-06-15d. Implementation in progress.**
