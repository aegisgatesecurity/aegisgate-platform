# TODO-303 (Agent Intent Signing) Code Review

**Date:** 2026-06-17
**Reviewer:** goose (self-review, post-implementation)
**Status:** 6 issues found — 2 critical, 3 medium, 1 minor. All 6 fixed and committed.

---

## TL;DR

The implementation is **functionally correct and ships-ready**, but I found 6 issues worth fixing — most of which I would have caught earlier if I had applied the lessons from the TODO-301/302 reviews more rigorously. The good news: most of these are 1-5 line fixes plus comment updates. The C2 (weak prefix validation) is the most important — it accepts non-hex characters in the shortfp position.

I applied all 6 fixes and verified the suite is green. The post-fix state is:
- 50+ unit tests (was 46; added 7 new tests for the C2 / m1 fixes)
- Coverage 91.6% (was 88.8%; up because the new tests cover more code paths)
- All 60 packages pass
- Race detector clean
- End-to-end CLI smoke test passes (sign + verify roundtrip)

---

## What was fixed (6 issues)

### C1. `buildIssuer` used the caller's original `tuple`, not the local copy `t`

**File:** `pkg/agentintentsign/sign.go`

The Sign() function copies the caller's tuple to a local `t` (to avoid mutating the caller's input — TODO-301 C3 lesson) and signs the local copy. But the call to `buildIssuer(tuple, keyID)` passed the original `tuple` instead of `&t`. In practice, this worked because `AgentID` is required, but the inconsistency was a code smell that could become a bug if we add more auto-fillable fields.

**Fix:** Pass `&t` to `buildIssuer`. One-line change.

### C2. `issuerMatchesAgent` had a weak prefix check (length 16, not hex validation; key_id not checked at all)

**File:** `pkg/agentintentsign/sign.go`

The check was:
```go
if parts[0] != "a2a-intent" || parts[1] != "shortfp" || len(parts[2]) != 16 {
    return false
}
```

It didn't validate:
- `parts[2]` is hex (could be `aaaaaaaaaaaaaaaa` and pass)
- `parts[3]` (the key_id) is non-empty

**Fix:** Added `isHexString` helper. The check is now:
```go
if !isHexString(parts[2]) || len(parts[2]) != 16 {
    return false
}
if parts[3] == "" {
    return false
}
```

Added 4 new tests for the new validation paths.

### M1. The agent_id regex comment was misleading

**File:** `pkg/agentintentsign/types.go`

The comment said `'v'` is "allowed as a standalone character (semver convention)", but the regex already includes `v` (it's a lowercase letter). The comment made `v` sound special.

**Fix:** Updated the comment to accurately describe the regex (ASCII letters, digits, and the punctuation characters). One comment update.

### M2. The "stale comment" in Verify about the agent-id prefix length

**File:** `pkg/agentintentsign/sign.go`

The comment said "last 32 chars of the issuer", but the implementation uses the FULL agent_id (via tail-match). Stale comment from an earlier design.

**Fix:** Updated the comment to match the implementation. One comment update.

### M3. The HTTP verify handlers (all 3 Tier 5) had no `expected_key_id` support (inconsistency with the CLI)

**Files:** `cmd/aegisgate-platform/{a2a_intent,aibom,evaluator}_http.go`

The CLI's `verify --key-id=K` checks that the envelope's key id matches. The HTTP handlers didn't accept this. An HTTP caller who wants to verify with a specific key id had no way to do so.

**Fix:** Added an optional `expected_key_id` query parameter to all 3 HTTP verify handlers. Consistent across all Tier 5 features.

### m1. The `TestVerify_ExpiredIntent` test was racy and didn't actually test the expiry check

**File:** `pkg/agentintentsign/sign_test.go`

The test used `time.Sleep(50 * time.Millisecond)` to wait for the 1ms-TTL intent to expire. Under `-race`, this was racy (the sleep races with the test scheduling). And the test's design meant it was actually testing the signature check, not the expiry check.

**Fix:** Added a `Clock` interface, a `VerifyWithClock(env, clock)` variant, and a `frozenClock` test helper. The expiry test now uses `VerifyWithClock` with a clock set 2 hours in the future — deterministic, no sleep. Deleted the old racy test.

This is the proper way to test time-dependent logic: inject a clock, not rely on `time.Sleep`. The lesson: **time-based tests should never call `time.Sleep`.**

---

## Validation (post-fix)

- ✅ `gofmt -l`: empty
- ✅ `go vet ./...`: 0 issues
- ✅ `go test -count=0 ./...`: 60 packages compile cleanly
- ✅ `go test -count=1 ./...`: 60/60 packages pass
- ✅ `go test -race ./pkg/agentintentsign/...`: clean
- ✅ Coverage: 91.6% on `pkg/agentintentsign` (up from 88.8%)
- ✅ `git diff go.mod`: empty (zero new external deps)
- ✅ End-to-end CLI smoke test: sign + verify roundtrip returns VALID

## What I learned that I should have caught in v0.1

1. **Don't pass the original parameter to a sub-function when a local copy exists** (C1). The `t` rename was supposed to enforce this, but `buildIssuer(tuple, ...)` slipped through.
2. **Validate the parts of a delimited string, not just the count** (C2). I checked `len(parts) == 4` but didn't validate the format of `parts[2]` (just its length) or even check that `parts[3]` is non-empty.
3. **API consistency across handlers** (M3). The `expectedKeyID` was in the CLI but not the HTTP — I should have applied this consistently across all three Tier 5 features.
4. **Update comments when you change the code** (M2). The "last 32 chars" comment was from a previous design.
5. **Time-based tests should never call `time.Sleep`** (m1). Inject a clock, not a sleep. This is the TODO-301 m4 lesson applied more rigorously.

## What worked well

- The TODO-301 C1 fix (functional options) was applied consistently
- The TODO-301 C3 fix (no caller-mutation) was applied via the `t := *tuple` shallow copy
- The TODO-301 M1 fix (subject kind check) was applied
- The TODO-302 C1 fix (WithKeyID in custom-issuer path) was applied
- The 5-component issuer format follows the established pattern
- Sentinel errors for `errors.Is` usage
- Cross-agent replay detection (the tail-match approach handles colons in agent_ids correctly)
- Race-detector tests all pass
