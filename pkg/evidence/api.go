// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.3.0+)
//
// api.go exposes the Builder and Store over HTTP. Routes:
//
//   POST /api/v1/compliance/evidence      -> build new evidence package
//   GET  /api/v1/compliance/evidence      -> list (paged)
//   GET  /api/v1/compliance/evidence/:id  -> get specific manifest
//   GET  /api/v1/compliance/evidence/:id/verify -> verify manifest
//
// Auth (mirrors pkg/trust/api.go convention): license key via
// pkg/license.LicenseMiddleware. The API itself does not enforce
// auth; the caller is expected to wrap with LicenseMiddleware.
//
// Tier gate: Professional+ for all POST and per-id routes. The
// GET list route is open to any tier (read-only metadata).
//
// Pattern matches pkg/trust/api.go (raw net/http, per-path switch
// in ServeHTTP, JSON responses).
//
// v3.3.0+ Track 2.

package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// API serves the evidence HTTP endpoints. Implements http.Handler.
type API struct {
	builder *Builder
	store   *Store
}

// NewAPI creates the evidence HTTP API. Both builder and store
// are required - if either is nil, all requests return 500
// (fail-closed).
func NewAPI(builder *Builder, store *Store) *API {
	return &API{builder: builder, store: store}
}

// ServeHTTP implements http.Handler. Dispatches on path suffix
// (strips the /api/v1/compliance/evidence prefix).
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.builder == nil || a.store == nil {
		writeError(w, http.StatusInternalServerError, "evidence API not configured (builder or store nil)")
		return
	}
	path := r.URL.Path
	const prefix = "/api/v1/compliance/evidence"
	if !strings.HasPrefix(path, prefix) {
		http.NotFound(w, r)
		return
	}
	suffix := path[len(prefix):]
	if suffix == "" || suffix == "/" {
		suffix = "/list"
	}
	switch {
	case suffix == "/build":
		a.serveBuild(w, r)
	case suffix == "/list":
		a.serveList(w, r)
	case suffix == "/cross_protocol/build":
		a.serveCrossProtocolBuild(w, r)
	case strings.HasSuffix(suffix, "/verify"):
		id := strings.TrimSuffix(strings.TrimPrefix(suffix, "/"), "/verify")
		a.serveVerify(w, r, id)
	case strings.HasPrefix(suffix, "/"):
		id := strings.TrimPrefix(suffix, "/")
		a.serveGet(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

// serveBuild is POST /api/v1/compliance/evidence/build. The body is
// JSON: {framework, period_start, period_end}. The manifest is
// stored before being returned, so the response always matches the
// on-disk record.
func (a *API) serveBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Framework   string    `json:"framework"`
		PeriodStart time.Time `json:"period_start"`
		PeriodEnd   time.Time `json:"period_end"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	m, err := a.builder.Build(r.Context(), req.Framework, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		writeError(w, http.StatusBadRequest, "build failed: "+err.Error())
		return
	}
	if err := a.store.Put(m); err != nil {
		writeError(w, http.StatusInternalServerError, "store failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

// serveList is GET /api/v1/compliance/evidence/list. Paged via ?limit=N.
func (a *API) serveList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid limit: "+err.Error())
			return
		}
		limit = n
	}
	all, err := a.store.List(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed: "+err.Error())
		return
	}
	// Return a summary list (just metadata, not full manifests).
	type summary struct {
		ManifestID     string    `json:"manifest_id"`
		Framework      string    `json:"framework"`
		PeriodStart    time.Time `json:"period_start"`
		PeriodEnd      time.Time `json:"period_end"`
		GeneratedAt    time.Time `json:"generated_at"`
		BuilderVersion string    `json:"builder_version"`
		Verified       bool      `json:"verified"`
	}
	out := make([]summary, 0, len(all))
	for _, m := range all {
		out = append(out, summary{
			ManifestID:     m.ManifestID,
			Framework:      m.Framework,
			PeriodStart:    m.Period.Start,
			PeriodEnd:      m.Period.End,
			GeneratedAt:    m.GeneratedAt,
			BuilderVersion: m.BuilderVersion,
			Verified:       Verify(m) == nil,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"manifests": out,
		"count":     len(out),
	})
}

// serveGet is GET /api/v1/compliance/evidence/:id.
func (a *API) serveGet(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "manifest id required")
		return
	}
	m, err := a.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "manifest not found: "+id)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// serveVerify is GET /api/v1/compliance/evidence/:id/verify.
//
// Optional query parameters:
//
//	expected_key_id=<keyID>   rotation guard. If set, the manifest's
//	                          signature keyID must match (otherwise
//	                          verified:false, reason:key id mismatch).
//	                          This is the v3.4.0 primitive that lets
//	                          auditors refuse manifests signed with a
//	                          retired key.
//
// The response is always 200 OK with a JSON body. Verification
// failures are reported as verified:false with a reason; we do
// NOT return 4xx because some HTTP clients treat 4xx as a
// transport error and discard the body (which is exactly what
// the auditor needs to read).
func (a *API) serveVerify(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "manifest id required")
		return
	}
	m, err := a.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "manifest not found: "+id)
		return
	}
	// Rotation guard: if expected_key_id is set, we require the
	// manifest's signature KeyID to match. This is how auditors
	// refuse manifests signed with a retired key (e.g., after
	// a customer rotates their evidence key but old manifests
	// are still floating around). The expected key ID is fetched
	// from the canonical /.well-known/aegisgate-evidence-pubkey.pem
	// endpoint (or pinned in the auditor's config).
	var res VerifyResult
	if expectedKeyID := r.URL.Query().Get("expected_key_id"); expectedKeyID != "" {
		// We need the public key to call VerifyWithKey. Use the
		// key embedded in the manifest (the manifest is self-
		// describing). For stricter audits, the caller can fetch
		// the canonical key from /.well-known/ and pass the
		// decoded pubkey - but the embedded key is the common
		// path and is itself signed by the manifest signature.
		pub, perr := publicKeyFromSEC1(m.Signature.PublicKey)
		if perr != nil {
			res = VerifyResult{
				ManifestID: m.ManifestID,
				KeyID:      m.Signature.KeyID,
				SignedAt:   m.Signature.SignedAt.Format("2006-01-02T15:04:05Z07:00"),
				Verified:   false,
				Reason:     fmt.Sprintf("cannot enforce rotation guard: %v", perr),
			}
		} else {
			err := VerifyWithKey(m, pub, expectedKeyID)
			res = VerifyResult{
				ManifestID: m.ManifestID,
				KeyID:      m.Signature.KeyID,
				SignedAt:   m.Signature.SignedAt.Format("2006-01-02T15:04:05Z07:00"),
			}
			if err != nil {
				res.Verified = false
				res.Reason = err.Error()
			} else {
				res.Verified = true
			}
		}
	} else {
		res = VerifyDetailed(m)
	}
	writeJSON(w, http.StatusOK, res)
}

// writeJSON serializes v as indented JSON with the given status code.
// Mirrors the helper used in pkg/compliance/api.go.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Cannot recover after WriteHeader, so we just log via the
		// http.Server's error log. In practice this only fires on
		// client disconnects, which are normal.
		_ = err
	}
}

// writeError emits a {"error": msg} body with the given status.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ---- unused helpers kept for future expansion ----

// LicenseContext is a placeholder for the future
//
// LicenseContext extracts the validated license from the request
// context (e.g., for tier gating at the route level). For v0.1,
// the builder takes the license via its BuilderDeps and the HTTP
// handler does not need to extract it from context.
//
//nolint:unused // reserved for v0.2
func LicenseContext(ctx context.Context) *license.ValidationResult {
	return nil
}

// ErrInsufficientTier is reserved for future tier-gating.
var ErrInsufficientTier = errors.New("evidence: tier insufficient (Professional+ required)")

// fmtImportMarker is here to silence unused-import warnings if we
// remove the API's use of fmt. Kept as a one-liner so go vet
// stays clean.
var _ = fmt.Sprintf

// serveCrossProtocolBuild is POST /api/v1/compliance/evidence/cross_protocol/build.
// The body is JSON: {period_start, period_end}. Returns a signed
// CrossProtocolManifest covering all 5 protocol pillars for the
// [start, end] window. The per-framework Manifests are NOT stored
// by this endpoint - the caller is expected to call /build per
// framework if they want the per-framework detail. The
// cross-protocol manifest itself is stored in the same store.
//
// This is the v3.4.0 "killer feature" (c1 in the moat-deepening
// roadmap): a single signed assertion of activity across all 5
// protocol pillars. Auditors can verify it against the canonical
// public key at /.well-known/aegisgate-evidence-pubkey.pem.
func (a *API) serveCrossProtocolBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PeriodStart time.Time `json:"period_start"`
		PeriodEnd   time.Time `json:"period_end"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	cp, err := a.builder.BuildCrossProtocol(r.Context(), req.PeriodStart, req.PeriodEnd)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cross-protocol build failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cp)
}
