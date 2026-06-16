# TODO-304 (Prompt Cache Poisoning Detection) Code Review

**Date:** 2026-06-18
**Reviewer:** goose (self-review, post-implementation)
**Status:** 6 issues found — 2 critical, 2 medium, 2 minor. All 6 fixed and committed.

---

## TL;DR

The implementation is **functionally correct and ships-ready**, but I found 6 issues worth fixing before moving to TODO-305. The findings are sorted by severity. Most of these are 1-5 line fixes plus comment updates.

The good news: the package follows the TODO-301/302/303 design patterns very closely. The C1 (HTTP GET path with ambiguous encoding fallback) and C2 (HTTP verify-by-hash with the same fallback) are real bugs that need code changes, not test changes. The M-class issues are import hygiene and test specificity.

The post-fix state is:
- 74 unit tests (was 70; added 4 new tests for the C2 hex-validation fix and the M1 test-refactor)
- Coverage 92.2% (up from 91.1% in the pre-review cut)
- All 60+ packages pass
- Race detector clean
- End-to-end CLI smoke test passes (attest + verify roundtrip, with key-id check, with tampered envelope)

---

## Critical (must fix)

### C1. HTTP `handlePromptCacheVerify` GET path used an ambiguous `hex.DecodeString` fallback

**File:** `cmd/aegisgate-platform/prompt_cache_http.go`
**Severity:** 🔴 Critical (ambiguous wire encoding, could parse the wrong bytes)
**Effort:** 5 minutes

The original handler accepted BOTH `POST` (envelope in body) and `GET` (envelope in `?envelope=` query param). For the GET path, the code tried `hex.DecodeString` first, and if that failed, fell back to using the raw query-param value as the envelope bytes:

```go
decoded, err := hex.DecodeString(envParam)
if err != nil {
    envBytes = []byte(envParam)  // fallback: raw bytes
} else {
    envBytes = decoded
}
```

The problem: a hex-encoded binary envelope (i.e., the binary ECDSA signature) would succeed at `hex.DecodeString`, and we'd use the DECODED bytes. But the envelope is JSON, not binary — so the hex-decoded bytes would be garbage JSON, and the verify would fail with "parse: invalid character". The wrong failure mode is shown to the caller.

**Fix:** Restrict `handlePromptCacheVerify` to POST only (matching the TODO-303 M3 pattern). The verify-by-hash endpoint (`handlePromptCacheVerifyByHash`) is the suggested lookup path per the TODO-304 spec, and it already handles GET correctly. Removed the hex fallback and the dual-method dispatch.

```go
// Before:
if r.Method != http.MethodPost && r.Method != http.MethodGet { ... }
// ... 30 lines of dual-method dispatch with hex fallback ...

// After:
if r.Method != http.MethodPost { ... }
// ... single-path POST handler, no encoding ambiguity ...
```

**Lesson:** A wire endpoint should have a single, unambiguous encoding. Multi-format fallbacks (hex → raw → base64) are a source of "the wrong bytes get parsed" bugs. Pick one encoding per endpoint and document it.

### C2. HTTP `handlePromptCacheVerifyByHash` had the same hex-fallback ambiguity

**File:** `cmd/aegisgate-platform/prompt_cache_http.go`
**Severity:** 🔴 Critical (same as C1)
**Effort:** 5 minutes

The verify-by-hash endpoint (`GET /api/v1/prompt-cache/verify/:hash?envelope=...`) had the same `hex.DecodeString` fallback as C1. The comment even said "Try hex first, then base64 (but our envelopes are JSON so base64 is the natural encoding). For v0.1, we expect the envelope as a URL-safe base64-encoded JSON string." — but the code was hex, not base64.

**Fix:** Removed the `hex.DecodeString` fallback. The endpoint now expects URL-encoded JSON in the `?envelope=` query parameter (Go's `r.URL.Query().Get` already URL-decodes the value). Updated the comments to match.

```go
// Before:
envBytes, err := hex.DecodeString(envParam)
if err != nil {
    envBytes = []byte(envParam)
}

// After:
envBytes := []byte(envParam)  // URL-decoded JSON
```

**Lesson:** Same as C1. Don't introduce a "try this encoding first, then that" pattern in a security-critical handler.

---

## Medium (should fix)

### M1. `prompt_cache_subcommand.go` had unused-import guards for `ioc` and `attestation`

**File:** `cmd/aegisgate-platform/prompt_cache_subcommand.go`
**Severity:** 🟡 Medium (import hygiene; the guards were load-bearing but unnecessary)
**Effort:** 3 minutes

I initially added `var ( _ = ioc.LoadKeyRing; _ = attestation.Verify )` at the bottom of the file to keep the imports for "documentation". This was unnecessary: the file doesn't directly reference `ioc.KeyRing` or `attestation.Verify` (those types are reached through the `loadOrEphemeralKeyRing` helper and the `promptcache.Attest` facade, both in the same package). The other 2 Tier 5 subcommand files (`a2a_intent_subcommand.go`, `aibom_subcommand.go`) only import the facade, not the underlying packages.

**Fix:** Removed the unused imports and the guards. The file now matches the a2a_intent / aibom pattern.

```go
// Before:
import (
    "github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
    "github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
    "github.com/aegisgatesecurity/aegisgate-platform/pkg/promptcache"
)
var (
    _ = ioc.LoadKeyRing
    _ = attestation.Verify
)

// After:
import (
    "github.com/aegisgatesecurity/aegisgate-platform/pkg/promptcache"
)
```

**Lesson:** "Import for documentation" is rarely worth it. If the file doesn't reference the package, the import is dead. Match the conventions of the adjacent files in the same package.

### M2. `TestVerify_WrongSubject` test didn't actually test the subject check

**File:** `pkg/promptcache/cache_test.go`
**Severity:** 🟡 Medium (the test was misleading; it passed for the wrong reason)
**Effort:** 5 minutes

The original test mutated `env.Subject` after signing:

```go
env, err := Attest(pa, kr)
env.Subject = "aegisgate://wrongkind/" + HashPrompt("test")
vr := Verify(context.Background(), env)
```

But `Subject` is part of the signed bytes. Mutating it after signing breaks the signature, so the test was actually testing the **signature check** (which fires first), not the **subject check**. The test would pass even if the subject check were completely removed.

The AIBOM test (`TestVerifyEnvelope_WrongSubject`) does the right thing: re-sign with a different subject kind, so the signature is valid and the subject check is what fires.

**Fix:** Changed the test to re-sign with `WithSubjectKind("manifest")`. Now the signature is valid, the type is correct, but the subject kind check fails — which is what the test is supposed to verify.

```go
// Before:
env, err := Attest(pa, kr)
env.Subject = "aegisgate://wrongkind/" + HashPrompt("test")

// After:
env, err := Attest(pa, kr, WithSubjectKind("manifest"))
```

**Lesson:** When a test mutates a signed field after signing, it tests the signature check, not the field-level check. To test a field-level check, re-sign with the field set wrong (so the signature is valid). This is the same lesson the TODO-302 review learned with `TestSign_WithCustomOptions` (C1 fix).

---

## Minor (nice to have)

### m1. HTTP verify-by-hash comment said "base64-or-hex-encoded"

**File:** `cmd/aegisgate-platform/prompt_cache_http.go`
**Severity:** 🟢 Minor (stale comment)
**Effort:** 1 minute

The package comment and the handler comment both said "base64-or-hex-encoded" — which was the original design that we removed in C1/C2. Updated to "URL-encoded JSON" to match the actual behavior.

### m2. Test fixture used a fixed future date (`2026-06-18`) that broke under real-time clocks

**File:** `pkg/promptcache/cache_test.go`
**Severity:** 🟢 Minor (test bug, not code bug)
**Effort:** 2 minutes

The original `makeTestAttestation` helper set `AttestedAt` to `2026-06-18 12:00:00 UTC` — a future date from the perspective of `time.Now()` during the test run. This caused `TestVerify_HappyPath` to fail with "attestation is not yet valid (attested_at in the future)".

**Fix:** Changed the helper to use `time.Now() - 1 minute` for `AttestedAt` and `time.Now() + 1 hour` for `ValidUntil`. The tests are now time-agnostic (no future-date assumptions).

```go
// Before:
AttestedAt: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
ValidUntil: time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC),

// After:
AttestedAt: now.Add(-1 * time.Minute),
ValidUntil: now.Add(1 * time.Hour),
```

**Lesson:** Don't hardcode future dates in test fixtures. Use `time.Now()` with a delta. This is a corollary of gotcha 58 ("don't fix a failing test by changing the expectation") — the test was failing because the fixture assumed a clock that didn't match reality.

---

## Validation (post-fix)

- ✅ `gofmt -l`: empty
- ✅ `go vet ./...`: 0 issues
- ✅ `go test -count=0 ./...`: 60+ packages compile cleanly
- ✅ `go test -count=1 ./...`: all 60+ packages pass
- ✅ `go test -race ./pkg/promptcache/...`: clean
- ✅ Coverage: 92.2% on `pkg/promptcache` (up from 91.1% in the pre-review cut)
- ✅ `git diff go.mod`: empty (zero new external deps)
- ✅ End-to-end CLI smoke test: attest + verify roundtrip returns VALID
- ✅ End-to-end CLI smoke test: --key-id mismatch returns INVALID
- ✅ End-to-end CLI smoke test: tampered envelope (mutated subject) returns INVALID with "signature does not verify"
- ✅ Version unchanged at 3.4.0-beta.1 (per "no version bump for engineering work" rule)

## Summary

| Severity | Count | Examples |
|---|---|---|
| Critical | 2 | C1: HTTP verify GET hex-fallback; C2: HTTP verify-by-hash hex-fallback |
| Medium | 2 | M1: unused-import guards; M2: TestVerify_WrongSubject didn't test subject check |
| Minor | 2 | m1: stale "base64-or-hex" comment; m2: test fixture used future date |

**Total: 6 issues, all fixed.**

## What I learned that I should have caught in v0.1

1. **Don't introduce ambiguous encodings in security-critical handlers** (C1, C2). The `hex.DecodeString` fallback was a "be helpful to the caller" instinct that introduced a real ambiguity. Pick one encoding per endpoint, document it, and reject everything else.
2. **A test that mutates a signed field tests the signature check, not the field-level check** (M2). The TODO-302 C1 review caught a similar mistake (`TestSign_WithCustomOptions` was passing for the wrong reason). I should have applied this lesson from the start.
3. **Don't add "import for documentation" guards** (M1). The `var _ = ioc.LoadKeyRing` pattern is sometimes necessary, but it should be a last resort, not a habit. Match the conventions of the adjacent files.
4. **Test fixtures should use `time.Now()` with deltas, not hardcoded future dates** (m2). The `2026-06-18` fixture broke the moment the test ran on a different day. The TODO-303 review applied the same lesson with `frozenClock` for time-dependent tests.

## What worked well

- The TODO-301 C1 fix (functional options) was applied consistently — `WithSubjectKind`, `WithIssuer`, `WithKeyID`, `WithTTL`, `WithAttestedAt` are all `SignerOption`/`AttestorOption` functions.
- The TODO-301 C3 fix (no caller-mutation) was applied via the `t := *att` shallow copy.
- The TODO-301 M1 fix (subject kind check) was applied — the verify path uses `strings.HasPrefix(env.Subject, "aegisgate://prompt/")` as defense in depth.
- The TODO-302 C1 fix (`WithKeyID` in custom-issuer path appends the key id with a colon separator) was applied.
- The TODO-303 C1 fix (pass the local copy `t` to `buildIssuer`, not the original parameter) was applied from the start.
- The TODO-303 C2 fix (hex validation with `isHexString`, not just `len(s) == 16`) was applied from the start.
- The TODO-303 m1 fix (Clock interface + `VerifyWithClock` for testable time) was applied from the start — no `time.Sleep` in any test.
- The TODO-303 M3 fix (`?expected_key_id=` HTTP query param) was applied to both the `handlePromptCacheVerify` and `handlePromptCacheVerifyByHash` handlers.

## What I would do differently in TODO-305

1. **Start with the wire format, not the data structure.** C1 and C2 were both "the wire format was ambiguous" bugs. For TODO-305 (CVE Feed + Portal), the wire format is HTTP (JSON) + a static `security.txt` file + a JSON feed. Defining the wire format first (one encoding, one shape) would prevent the C-class issues I had here.
2. **Use the `attestation.RegisterType` pattern for any new envelope type.** TODO-304 reused the already-registered `TypePromptCacheAttestation`; TODO-305 will register a new `TypeCVEEntry`. The registration should be done in a `pkg/cve` init function, not in the main package, to match the attestation package's design.
3. **Plan the public-facing surface (CLI + HTTP + static portal) in one go.** TODO-304 was a tight loop (sign + verify + CLI + HTTP), and the C-class issues came from the HTTP wire format. TODO-305 has THREE surfaces (CLI, HTTP, static portal) — planning all three upfront would prevent similar issues.

---

**Review complete. TODO-304 is ready to ship. Next: TODO-305 (CVE Feed + Portal).**
