// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Audit Log Search HTTP endpoints (v3.x close-out,
// Work Item 11, commit 4 of 4)
// =========================================================================
//
// audit_search_http.go wires pkg/audit's Searcher into the HTTP API as
//
//   - GET /api/v1/audit/search?from=&to=&user=&action=&severity=&type=&limit=&offset=&sort=
//   - GET /api/v1/audit/events/:id
//   - GET /api/v1/audit/users/:user/timeline
//   - GET /api/v1/audit/stats
//
// The Searcher is built in commit 3 of 4 (pkg/audit/handler.go,
// commit 8444b5c) and uses pkg/logging.RingBuffer as its event
// source. The /audit prefix alias is also registered so the
// auditor-on-a-plane scenario (no /api/v1 prefix) works too.
//
// v1 scope:
//   - Read-only. The Searcher is given a snapshot of the in-memory
//     ring buffer on each request; no state is mutated.
//   - GET only. Other methods return 405 (handler-level enforcement).
//   - License-gated via authMW.RequireAuth (same as the posture and
//     attestation endpoints). The Searcher itself does not enforce
//     tier; the gate is the middleware.
//
// The Searcher is stored in package-level vars (set by
// wireAuditSearchHandlers) so the four route handlers can reach it
// without an explicit closure capture. This mirrors the pattern in
// posture_http.go and keeps the wire*Handlers signature flat
// (mux, authMW, licenseMgr, eventSource) — same as the other v3.4.0+
// feature HTTP wirings.
// =========================================================================

package main

import (
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/audit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// auditSearcher is the audit log searcher used by the HTTP
// handlers. Set by wireAuditSearchHandlers. The audit.EventSource
// interface is satisfied by *logging.RingBuffer (Go's structural
// typing — the RingBuffer implements evidence.EventSource which
// has the same SnapshotBetween signature, so it transparently
// satisfies audit.EventSource too).
//
//nolint:unused // assigned at wire time
var auditSearcher *audit.Searcher

// wireAuditSearchHandlers registers the /api/v1/audit/* HTTP routes.
// Call this from main() after the audit ring buffer and the
// license manager are initialized, and before the HTTP server
// starts listening.
//
// eventSource must be non-nil. Typically this is the *logging.RingBuffer
// that the platform uses as its audit event recorder (the same one
// the SIEM dispatcher reads from). If eventSource is nil the
// handlers return 500 (fail-closed, same as the compliance API
// pattern in pkg/audit/handler.go).
//
// licenseMgr must be non-nil. The Searcher requires a non-nil
// license.Manager at construction time (its ServeHTTP returns
// 500 if either source or manager is nil). The auth middleware
// does the actual license-gating; the manager is held by the
// Searcher for consistency with the other audit subcommands
// (e.g., pkg/audit/siem_dispatcher.go).
//
// This is commit 4 of 4 for the v3.x close-out Work Item 11
// (audit log search). The Searcher type and the in-process
// matcher/pagination were added in commits 1-3 (e9a342c, f40ef36,
// 8444b5c). This commit completes the feature by exposing it
// over HTTP.
func wireAuditSearchHandlers(mux *http.ServeMux, authMW *auth.Middleware, eventSource audit.EventSource, licenseMgr *license.Manager) {
	auditSearcher = audit.NewSearcher(eventSource, licenseMgr)

	// Both /api/v1/audit/ and /audit/ are mounted. The Searcher
	// itself handles prefix stripping (see commit 3 fix #3 in
	// AUDIT-LOG-SEARCH-COMMIT-3-RESOLVED.md).
	//
	// RequireAuth takes a http.HandlerFunc (not http.Handler), so
	// we adapt the Searcher via its ServeHTTP method. The adapter
	// is cheap: it's just a type-conversion, no extra goroutine
	// or buffering.
	auditHandler := http.HandlerFunc(auditSearcher.ServeHTTP)
	mux.Handle("/api/v1/audit/", authMW.RequireAuth(auditHandler))
	mux.Handle("/audit/", authMW.RequireAuth(auditHandler))
}
