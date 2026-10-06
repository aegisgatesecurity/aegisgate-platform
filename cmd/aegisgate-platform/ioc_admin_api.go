// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library Admin API (v3.5.0+ Track 6)
// =========================================================================
//
// ioc_admin_api.go implements the admin API endpoints for the
// Federated IOC library. The endpoints are mounted on the
// dashboard mux (not the proxy mux) so they are reachable on
// the admin port (default 8443) and not on the public proxy
// port (default 8080). The endpoints are NOT exposed to the
// proxy traffic.
//
// Endpoints:
//
//	GET  /api/v1/ioc/admin/status
//	  Returns the current state: share/receive flags, keyring
//	  active keys, reputation summary, IOC store size, and
//	  producer stats.
//
//	POST /api/v1/ioc/admin/share
//	  Body: {"enabled": true|false}
//	  Toggles the share flag at runtime. No restart required.
//
//	POST /api/v1/ioc/admin/receive
//	  Body: {"enabled": true|false}
//	  Toggles the receive flag at runtime. Tier gate is still
//	  enforced; a Community/Developer instance returns 403.
//
//	POST /api/v1/ioc/admin/keyring/rotate
//	  Generates a new key, marks the current as retired, and
//	  returns the new keyId. The new key takes effect for all
//	  new signed bundles immediately.
//
//	GET  /api/v1/ioc/admin/keyring
//	  Returns the active keyring (redacted; no private key).
//
//	GET  /api/v1/ioc/admin/reputation
//	  Returns the per-peer reputation records.
//
//	GET  /api/v1/ioc/admin/feeds
//	  Returns statistics for all configured external TAXII feeds.
//
//	GET  /api/v1/ioc/admin/quarantine
//	  Returns quarantined vs active IOC counts.
//
//	POST /api/v1/ioc/admin/quarantine
//	  Body: {"action":"promote","sourcePrefix":"peer:instance-abc"}
//	  Promotes (un-quarantines) IOCs from the given source.
//
// All endpoints are JSON in / JSON out. The admin API does not
// require its own authentication beyond what the dashboard mux
// already enforces (the dashboard is typically behind OIDC +
// the tier gate; see docs/a2a-security-middleware-design.md for
// the existing dashboard auth pattern).
//
// v4.5.1+ Phase 4: When AEGISGATE_IOC_ADMIN_TOKEN is set, a
// bearer token is additionally required (defense in depth).
// When unset, the dashboard auth middleware is the only layer.
//
// v3.5.0+ Track 6 Task 5.
// =========================================================================

package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

// iocAdminAPI is the IOC admin API handler. Constructed with
// a pointer to the live iocWiring so the endpoints see the
// current state of share/receive/keyring/etc.
type iocAdminAPI struct {
	wiring     *iocWiring
	mu         sync.RWMutex
	adminToken string // v4.5.1+ Phase 4: bearer token for admin API; "" = no token auth
}

// newIOCAdminAPI creates an iocAdminAPI bound to the given
// wiring. Returns nil if wiring is nil (caller must check).
//
// v4.5.1+ Phase 4: reads AEGISGATE_IOC_ADMIN_TOKEN env var.
// When set, all admin API requests must include a matching
// Authorization: Bearer <token> header. When unset, no token
// auth is enforced (the existing dashboard auth middleware
// is the only auth layer).
func newIOCAdminAPI(w *iocWiring) *iocAdminAPI {
	return &iocAdminAPI{
		wiring:     w,
		adminToken: os.Getenv("AEGISGATE_IOC_ADMIN_TOKEN"),
	}
}

// Handler returns the http.Handler that serves the admin
// endpoints. Mount under /api/v1/ioc/admin/ on the dashboard
// mux.
//
// v4.5.1+ Phase 4: When adminToken is set, all endpoints are
// wrapped with requireAdminToken which checks for a matching
// Authorization: Bearer <token> header. This is a defense-in-
// depth layer on top of the existing dashboard auth middleware.
func (a *iocAdminAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ioc/admin/status", a.handleStatus)
	mux.HandleFunc("/api/v1/ioc/admin/share", a.handleShare)
	mux.HandleFunc("/api/v1/ioc/admin/receive", a.handleReceive)
	mux.HandleFunc("/api/v1/ioc/admin/keyring", a.handleKeyring)
	mux.HandleFunc("/api/v1/ioc/admin/keyring/rotate", a.handleKeyringRotate)
	mux.HandleFunc("/api/v1/ioc/admin/reputation", a.handleReputation)
	mux.HandleFunc("/api/v1/ioc/admin/feeds", a.handleFeeds)
	mux.HandleFunc("/api/v1/ioc/admin/quarantine", a.handleQuarantine)
	if a.adminToken == "" {
		return mux
	}
	return a.requireAdminToken(mux)
}

// requireAdminToken wraps an http.Handler with a bearer token
// check. Returns 401 if the Authorization header is missing or
// doesn't match the configured admin token. Uses constant-time
// comparison to prevent timing attacks.
//
// v4.5.1+ Phase 4: Hardening.
func (a *iocAdminAPI) requireAdminToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSONResponse(w, http.StatusUnauthorized, map[string]interface{}{
				"error":   "unauthorized",
				"message": "Authorization header required",
			})
			return
		}
		const prefix = "Bearer "
		if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSONResponse(w, http.StatusUnauthorized, map[string]interface{}{
				"error":   "unauthorized",
				"message": "Bearer token required",
			})
			return
		}
		token := strings.TrimSpace(authHeader[len(prefix):])
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.adminToken)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSONResponse(w, http.StatusUnauthorized, map[string]interface{}{
				"error":   "unauthorized",
				"message": "invalid admin token",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleStatus returns the current IOC library state.
func (a *iocAdminAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	wiring := a.wiring
	a.mu.RUnlock()
	if wiring == nil {
		http.Error(w, "IOC library not initialized", http.StatusServiceUnavailable)
		return
	}
	stats := wiring.Producer.Stats()
	canReceive, reason := wiring.Sync.CanReceive()
	resp := map[string]interface{}{
		"initialized":      true,
		"share":            wiring.Sync.IsShare(),
		"receive":          wiring.Sync.IsReceive(),
		"canReceive":       canReceive,
		"canReceiveReason": reasonOrEmpty(reason),
		"iocCount":         wiring.Store.Size(),
		"peers":            wiring.Sync.Peers(),
		"producer": map[string]interface{}{
			"enabled":        stats.Enabled,
			"eventsObserved": stats.EventsObserved,
			"eventsRecorded": stats.EventsRecorded,
			"eventsRejected": stats.EventsRejected,
		},
		"keyring": wiring.Sync.ActiveKeys(),
	}
	if wiring.Sync.Reputation() != nil {
		resp["reputation"] = wiring.Sync.Reputation()
	}
	// v4.5.1+: IOC feedback loop checker stats
	if wiring.Checker != nil {
		cs := wiring.Checker.Stats()
		resp["feedbackLoop"] = map[string]interface{}{
			"storeSize":       cs.StoreSize,
			"peerIOCs":        cs.PeerIOCs,
			"externalIOCs":    cs.ExternalIOCs,
			"localIOCs":       cs.LocalIOCs,
			"quarantinedIOCs": cs.QuarantinedIOCs,
			"minPeerCount":    cs.Config.MinPeerCount,
			"minSeverity":     string(cs.Config.MinSeverity),
			"conservative":    cs.Config.RequireLocalDetection,
		}
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

// handleShare toggles the share flag at runtime.
func (a *iocAdminAPI) handleShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	wiring := a.wiring
	a.mu.RUnlock()
	if wiring == nil {
		http.Error(w, "IOC library not initialized", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(),
			http.StatusBadRequest)
		return
	}
	wiring.Sync.SetShare(body.Enabled)
	// When enabling share, also enable the producer so the
	// store starts accumulating IOCs to serve.
	if body.Enabled {
		wiring.Producer.SetEnabled(true)
	}
	logIOCAdmin("share", body.Enabled, nil)
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"share": wiring.Sync.IsShare(),
	})
}

// handleReceive toggles the receive flag at runtime. Returns
// 403 if the instance is below Professional tier.
func (a *iocAdminAPI) handleReceive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	wiring := a.wiring
	a.mu.RUnlock()
	if wiring == nil {
		http.Error(w, "IOC library not initialized", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(),
			http.StatusBadRequest)
		return
	}
	// Tier gate: refuse to enable receive on a sub-Professional
	// tier, even via the admin API. The platform license is
	// the source of truth.
	//
	// We set the flag first, then check CanReceive(), then
	// revert on failure. This is the v3.4.0 fix for the cold-
	// start 403: previously the handler checked CanReceive()
	// BEFORE setting the flag, but CanReceive() requires the
	// flag to be on, so a fresh Professional instance could
	// not first-time-enable receive via the dashboard. The
	// revert-on-failure preserves the security model: a
	// sub-Professional tier (Community/Developer) calling
	// this endpoint still gets a 403 and the flag stays off.
	if body.Enabled {
		wiring.Sync.SetReceive(true)
		ok, reason := wiring.Sync.CanReceive()
		if !ok {
			wiring.Sync.SetReceive(false)
			logIOCAdmin("receive", body.Enabled, reason)
			http.Error(w, fmt.Sprintf("cannot enable receive: %v", reason),
				http.StatusForbidden)
			return
		}
	} else {
		wiring.Sync.SetReceive(false)
	}
	// When enabling receive, also enable the producer so the
	// local store is ready to receive incoming bundles.
	if body.Enabled {
		wiring.Producer.SetEnabled(true)
	}
	logIOCAdmin("receive", body.Enabled, nil)
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"receive": wiring.Sync.IsReceive(),
	})
}

// handleKeyring returns the active keys (redacted).
func (a *iocAdminAPI) handleKeyring(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	wiring := a.wiring
	a.mu.RUnlock()
	if wiring == nil {
		http.Error(w, "IOC library not initialized", http.StatusServiceUnavailable)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"keys": wiring.Sync.ActiveKeys(),
	})
}

// handleKeyringRotate generates a new key, retiring the current.
func (a *iocAdminAPI) handleKeyringRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	wiring := a.wiring
	a.mu.RUnlock()
	if wiring == nil {
		http.Error(w, "IOC library not initialized", http.StatusServiceUnavailable)
		return
	}
	newKeyID, err := wiring.Sync.RotateKey()
	if err != nil {
		logIOCAdmin("rotate-key", false, err)
		http.Error(w, "rotate key: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	logIOCAdmin("rotate-key", true, nil)
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"newKeyId": newKeyID,
		"keys":     wiring.Sync.ActiveKeys(),
	})
}

// handleReputation returns the per-peer reputation records.
func (a *iocAdminAPI) handleReputation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	wiring := a.wiring
	a.mu.RUnlock()
	if wiring == nil {
		http.Error(w, "IOC library not initialized", http.StatusServiceUnavailable)
		return
	}
	rep := wiring.Sync.Reputation()
	if rep == nil {
		http.Error(w, "reputation not enabled", http.StatusNotFound)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"peers": rep,
	})
}

// writeJSONResponse writes v as a JSON response with the
// given status code. Uses the package-level writeJSON helper
// where possible.
func writeJSONResponse(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// reasonOrEmpty returns the error's message, or "" if the
// error is nil. Used for embedding "reason" fields in JSON
// responses.
func reasonOrEmpty(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// logIOCAdmin is a small audit-log helper for IOC admin
// actions. Wired to the platform's standard log package.
// (Future iteration: write to the audit ring buffer so the
// action shows up in compliance evidence packages.)
func logIOCAdmin(action string, value bool, err error) {
	if err == nil {
		log.Printf("[IOC-ADMIN] %s=%v", action, value)
	} else {
		log.Printf("[IOC-ADMIN] %s=%v: %v", action, value, err)
	}
}

// handleFeeds returns statistics for all configured external
// TAXII feeds. GET /api/v1/ioc/admin/feeds
func (a *iocAdminAPI) handleFeeds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	wiring := a.wiring
	a.mu.RUnlock()
	if wiring == nil {
		http.Error(w, "IOC library not initialized", http.StatusServiceUnavailable)
		return
	}
	if wiring.FeedManager == nil {
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"feeds":   []interface{}{},
		})
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"enabled": true,
		"feeds":   wiring.FeedManager.Stats(),
	})
}

// handleQuarantine manages soft-quarantined IOCs.
//
// GET  /api/v1/ioc/admin/quarantine
//
//	Returns quarantined vs active IOC counts.
//
// POST /api/v1/ioc/admin/quarantine
//
//	Body: {"action":"promote","sourcePrefix":"peer:instance-abc"}
//	Promotes (un-quarantines) all IOCs from the given source peer.
//	Returns the number of IOCs promoted.
//
// v4.5.1+ Phase 4: Hardening — soft quarantine.
func (a *iocAdminAPI) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	wiring := a.wiring
	a.mu.RUnlock()
	if wiring == nil {
		http.Error(w, "IOC library not initialized", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		q, active := wiring.Store.QuarantineStats()
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"quarantined": q,
			"active":      active,
		})
	case http.MethodPost:
		var body struct {
			Action       string `json:"action"`
			SourcePrefix string `json:"sourcePrefix"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(),
				http.StatusBadRequest)
			return
		}
		if body.Action != "promote" {
			http.Error(w, `{"error":"bad_request","message":"action must be 'promote'"}`,
				http.StatusBadRequest)
			return
		}
		if body.SourcePrefix == "" {
			http.Error(w, `{"error":"bad_request","message":"sourcePrefix required"}`,
				http.StatusBadRequest)
			return
		}
		n := wiring.Store.PromoteQuarantined(body.SourcePrefix)
		logIOCAdmin("promote-quarantined", n > 0, nil)
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"promoted":     n,
			"sourcePrefix": body.SourcePrefix,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
