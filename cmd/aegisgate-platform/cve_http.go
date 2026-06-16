// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CVE Entry HTTP endpoint (TODO-305)
//
// cve_http.go wires pkg/cve into the HTTP API as
//   - POST /api/v1/cve/publish
//   - POST /api/v1/cve/verify
//
// TIER GATING: The publish side is Enterprise-only
// (per the user's confirmation on 2026-06-18). The
// verify side is free (verifying a CVE entry is a
// public action). The tier check is done inline using
// auth.GetTier (the request context carries the
// authenticated user's tier string).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/cve"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// wireCVEHandlers registers the /api/v1/cve/* HTTP
// routes. The keyring is shared with the other Tier 5
// endpoints (TODO-301/302/303/304).
//
// TIER GATING: The publish side is Enterprise-only
// (per the user's confirmation on 2026-06-18). The
// verify side is free (verifying a CVE entry is a
// public action). The tier check is done inline (the
// auth.Middleware exposes a "tier" string in the
// request context; the handler checks it for
// "enterprise" only).
func wireCVEHandlers(mux *http.ServeMux, authMW *auth.Middleware, kr *ioc.KeyRing) {
	// Publish: Enterprise-only.
	mux.HandleFunc("/api/v1/cve/publish", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		// Tier check.
		if tierStr := auth.GetTier(r.Context()); tierStr != "enterprise" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":    "CVE publishing is Enterprise-only",
				"tier":     tierStr,
				"required": "enterprise",
			})
			return
		}
		handleCVEPublish(w, r, kr)
	}))
	// Verify: free (no tier gate).
	mux.HandleFunc("/api/v1/cve/verify", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleCVEVerify(w, r)
	}))
}

// handleCVEPublish is the HTTP handler for
// POST /api/v1/cve/publish. The request body is a
// JSON object with the CVE entry fields:
//
//	{
//	  "id":           "AEGIS-2026-0001",
//	  "title":        "...",
//	  "description":  "...",
//	  "affected":     ["anthropic/claude-3-5-sonnet@<20241022"],
//	  "fixed":        ["anthropic/claude-3-5-sonnet@20241022"],
//	  "score":        7.5,
//	  "vector":       "CVSS:3.1/AV:N/...",
//	  "references":   ["https://..."],
//	  "mitigations":  ["..."],
//	  "discovered_by": "AegisGate Research",
//	  "disclosed_at":  "2026-06-01T00:00:00Z",
//	  "withdrawn_at":  "2026-06-05T00:00:00Z"   // optional
//	}
//
// The response is the signed envelope (JSON).
func handleCVEPublish(w http.ResponseWriter, r *http.Request, kr *ioc.KeyRing) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 64KB max (CVE entries are small; 64KB
	// accommodates a generous description).
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	var req struct {
		ID           string    `json:"id"`
		Title        string    `json:"title"`
		Description  string    `json:"description"`
		Affected     []string  `json:"affected"`
		Fixed        []string  `json:"fixed"`
		Score        float64   `json:"score"`
		Vector       string    `json:"vector"`
		References   []string  `json:"references"`
		Mitigations  []string  `json:"mitigations"`
		DiscoveredBy string    `json:"discovered_by"`
		DisclosedAt  time.Time `json:"disclosed_at"`
		WithdrawnAt  time.Time `json:"withdrawn_at"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse body: " + err.Error()})
		return
	}
	// Required fields.
	if req.ID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "id is required"})
		return
	}
	if req.Title == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "title is required"})
		return
	}
	if req.Description == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "description is required"})
		return
	}
	if req.DiscoveredBy == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "discovered_by is required"})
		return
	}
	// Build the entry.
	entry := &cve.CVEEntry{
		ID:           req.ID,
		Title:        req.Title,
		Description:  req.Description,
		Affected:     req.Affected,
		Fixed:        req.Fixed,
		Score:        req.Score,
		Vector:       req.Vector,
		References:   req.References,
		Mitigations:  req.Mitigations,
		DiscoveredBy: req.DiscoveredBy,
		DisclosedAt:  req.DisclosedAt,
		WithdrawnAt:  req.WithdrawnAt,
	}
	// Publish. TTL=0 means no expiration (CVE entries
	// are immutable).
	env, err := cve.Publish(entry, kr, 0)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "publish: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(env)
}

// handleCVEVerify is the HTTP handler for
// POST /api/v1/cve/verify. The request body is the
// JSON-encoded envelope. The response is a flat JSON
// shape derived from cve.VerifyResult.
//
// Supports an optional `expected_key_id` query
// parameter (M3 from TODO-303, applied to TODO-305).
func handleCVEVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 1MB max (envelope is small).
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	vr, err := cve.VerifyJSON(context.Background(), body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse: " + err.Error()})
		return
	}
	// Optional expected_key_id check.
	if expectedKeyID := r.URL.Query().Get("expected_key_id"); expectedKeyID != "" {
		if vr.Valid && vr.Envelope.Signature.KeyID != expectedKeyID {
			vr.Valid = false
			vr.Reason = fmt.Sprintf("key ID mismatch: have %q, want %q",
				vr.Envelope.Signature.KeyID, expectedKeyID)
		}
	}
	if !vr.Valid {
		w.WriteHeader(http.StatusUnprocessableEntity)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(cveHTTPVerifyResultJSON(vr))
}

// cveHTTPVerifyResultJSON is the flat JSON-friendly
// shape of cve.VerifyResult, used by the HTTP verify
// endpoint.
type cveHTTPVerifyResultJSONShape struct {
	Valid        bool   `json:"valid"`
	Reason       string `json:"reason,omitempty"`
	Type         string `json:"type,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	ID           string `json:"id,omitempty"`
	Title        string `json:"title,omitempty"`
	Score        string `json:"score,omitempty"`
	Band         string `json:"band,omitempty"`
	DiscoveredBy string `json:"discovered_by,omitempty"`
	IsWithdrawal bool   `json:"is_withdrawal,omitempty"`
}

// cveHTTPVerifyResultJSON converts a VerifyResult to
// the HTTP-friendly shape.
func cveHTTPVerifyResultJSON(vr *cve.VerifyResult) cveHTTPVerifyResultJSONShape {
	out := cveHTTPVerifyResultJSONShape{
		Valid:  vr.Valid,
		Reason: vr.Reason,
	}
	if vr.Envelope != nil {
		out.Type = string(vr.Envelope.Type)
		out.Subject = vr.Envelope.Subject
		out.Issuer = vr.Envelope.Issuer
		out.KeyID = vr.Envelope.Signature.KeyID
	}
	if vr.Entry != nil {
		out.ID = vr.Entry.ID
		out.Title = vr.Entry.Title
		out.DiscoveredBy = vr.Entry.DiscoveredBy
		if vr.Entry.Score > 0 {
			out.Score = fmt.Sprintf("%.1f", vr.Entry.Score)
			out.Band = vr.Entry.Band
		}
	}
	out.IsWithdrawal = vr.IsWithdrawal
	return out
}
