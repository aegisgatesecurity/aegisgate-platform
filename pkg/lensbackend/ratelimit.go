// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Rate Limiting
// =========================================================================
//
// ratelimit.go wraps the Platform's existing rate limiter
// (upstream/aegisgate/pkg/resilience/ratelimit) with the
// Lens-specific semantics:
//
//   - Per-installation: 100 events/minute (client-side enforced
//     by the extension; server-side verified as a defense in depth).
//   - Global: 10000 events/minute (the LENS_RATE_LIMIT_PER_MIN
//     env var, default 10000).
//
// The per-installation key is the HMAC-SHA-256 of a per-installation
// secret (derived from the LENS_HMAC_KEY env var) under the
// claimed domain_hash. The global key is a constant string.
//
// Why a thin wrapper instead of a hand-rolled token bucket:
//
//   - The Platform's existing ratelimit package is already
//     vendored under upstream/aegisgate/pkg/resilience/ratelimit
//     and the Platform's go.mod includes it via a replace
//     directive. It is a "first-party" package from the Lens's
//     perspective (it lives in the same monorepo).
//   - Re-implementing the token bucket algorithm in stdlib would
//     be ~80 LOC of code that we'd then have to test and maintain.
//     Reusing the Platform's implementation means the Lens gets
//     the same behavior as the rest of the Platform, for free.
//   - The Platform's ratelimit uses golang.org/x/time/rate, which
//     is already in the Platform's go.sum (indirect, via
//     golang.org/x/time). The stdlib-or-first-party-or-Platform
//     constraint allows this because it's in the Platform's
//     existing closed dep set.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/resilience/ratelimit"
)

// ClientRateLimitPerMin is the per-installation events/minute cap.
// Matches the client-side limit enforced by the extension (see
// plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md §10.2).
const ClientRateLimitPerMin = 100

// GlobalRateLimitPerMin is the server-wide events/minute cap across
// all installations. Set from LENS_RATE_LIMIT_PER_MIN; default 10000.
const GlobalRateLimitPerMin = 10000

// LensRateLimiter is the Lens backend's rate limiter. It enforces
// the per-installation limit (ClientRateLimitPerMin) and the global
// limit (GlobalRateLimitPerMin) using two underlying
// ratelimit.RateLimiter instances.
type LensRateLimiter struct {
	mu         sync.RWMutex
	perInstall *ratelimit.RateLimiter
	global     *ratelimit.RateLimiter
	hmacKey    []byte
}

// NewLensRateLimiter creates a LensRateLimiter. The hmacKey is
// used to derive per-installation identifiers; if nil, the
// per-installation rate limiting falls back to the client IP.
func NewLensRateLimiter(hmacKey []byte, globalPerMin int) *LensRateLimiter {
	return &LensRateLimiter{
		perInstall: ratelimit.New(&ratelimit.Config{
			RequestsPerSecond: float64(ClientRateLimitPerMin) / 60.0,
			BurstSize:         ClientRateLimitPerMin,
			BlockDuration:     1 * time.Minute,
		}),
		global: ratelimit.New(&ratelimit.Config{
			RequestsPerSecond: float64(globalPerMin) / 60.0,
			BurstSize:         globalPerMin,
			BlockDuration:     1 * time.Minute,
		}),
		hmacKey: hmacKey,
	}
}

// AllowInstallation reports whether the given installation (identified
// by its claimed domain_hash) is allowed to send an event right now.
// Returns true if allowed, false if the per-installation limit has
// been exceeded.
func (l *LensRateLimiter) AllowInstallation(domainHash string) bool {
	key := l.installationKey(domainHash)
	return l.perInstall.Allow(key)
}

// AllowGlobal reports whether the server is allowed to accept an
// event right now (global rate limit).
func (l *LensRateLimiter) AllowGlobal() bool {
	return l.global.Allow("__lens_global__")
}

// installationKey derives the rate-limit key for a given installation.
// If an HMAC key is configured, the key is HMAC-SHA-256(domain_hash, key).
// Otherwise, the key is the domain_hash itself. The HMAC form prevents
// a malicious client from enumerating other installations' rate-limit
// buckets by guessing their domain_hash.
func (l *LensRateLimiter) installationKey(domainHash string) string {
	if len(l.hmacKey) == 0 {
		return domainHash
	}
	mac := hmac.New(sha256.New, l.hmacKey)
	mac.Write([]byte(domainHash))
	return hex.EncodeToString(mac.Sum(nil))
}

// GlobalMiddleware returns an http.Handler middleware that enforces
// the GLOBAL rate limit only. The per-installation limit is checked
// inside HandleTelemetry after the body is decoded (so the
// domain_hash from the event body — not a header — is the bucket
// key). This split was made on 2026-06-22 during pen-test Day 11
// after the original Middleware was found to read a header that
// HandleTelemetry set after the middleware had already run, leaving
// the per-installation limit silently disabled in production.
func (l *LensRateLimiter) GlobalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.AllowGlobal() {
			writeTooManyRequests(w, "global rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware is preserved as a synonym for GlobalMiddleware so
// existing callers (e.g. server.go's wiring) continue to compile.
// New code should call GlobalMiddleware directly.
//
// Deprecated: prefer GlobalMiddleware. The per-installation check
// cannot live in a generic middleware because it requires the
// decoded event body, which the middleware cannot see without
// duplicating the JSON decode.
func (l *LensRateLimiter) Middleware(next http.Handler) http.Handler {
	return l.GlobalMiddleware(next)
}

// CheckInstallation enforces the per-installation rate limit for
// the given domain_hash. Returns true if the event should be
// accepted, false if the per-installation bucket is exhausted.
// Called by HandleTelemetry after body decode + domain_hash
// verification.
func (l *LensRateLimiter) CheckInstallation(domainHash string) bool {
	return l.AllowInstallation(domainHash)
}

// writeTooManyRequests is a small helper to write a 429 response.
// Extracted so the error path is consistent across all rate-limit
// failures. The response body is a small JSON object with a
// machine-readable reason field.
func writeTooManyRequests(w http.ResponseWriter, reason string) {
	w.Header().Set("Retry-After", "60")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(w, `{"error":"rate_limit_exceeded","reason":%q}`+"\n", reason)
}
