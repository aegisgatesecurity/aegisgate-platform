// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Trust Portal: HTTP handlers
// =========================================================================
//
// portal.go implements the 4 public, no-auth HTTP routes for the
// trust portal:
//
//   GET /trust                       -> the HTML page (index.html)
//   GET /trust/api/posture           -> JSON: PostureSnapshot (60s cache)
//   GET /trust/api/frameworks        -> JSON: FrameworksSnapshot (60s cache)
//   GET /trust/api/uptime            -> JSON: UptimeSnapshot (1h cache)
//
// The data source is a Source interface (defined below). The wire
// function in cmd/aegisgate-platform/trust_portal_http.go provides
// the real implementation (adapters over pkg/posture.Checker and
// pkg/compliance.Manager). Tests provide a stub Source.
//
// All routes are GET-only. The handlers do not require authentication
// (this is a public marketing/operational page). The CSP-compatible
// HTML page can poll the JSON endpoints every 60s.
// =========================================================================

package trustportal

import (
	"encoding/json"
	"net/http"
	"time"
)

// Default cache TTLs. Overridable via Portal.Config.
const (
	DefaultPostureTTL    = 60 * time.Second
	DefaultFrameworksTTL = 60 * time.Second
	DefaultUptimeTTL     = 1 * time.Hour
)

// Source is the data source for the trust portal. The wire function
// in cmd/aegisgate-platform provides a real implementation backed by
// pkg/posture.Checker and pkg/compliance.Manager. Tests provide a
// stub.
type Source interface {
	// Posture returns the current posture report. The trust portal
	// uses this for /trust/api/posture and /trust/api/uptime.
	Posture() (*PostureSnapshot, error)
	// Frameworks returns the current frameworks snapshot. The trust
	// portal uses this for /trust/api/frameworks.
	Frameworks() (*FrameworksSnapshot, error)
	// Uptime returns the current uptime snapshot.
	Uptime() (*UptimeSnapshot, error)
}

// Portal is the HTTP-facing entry point. It owns the 3 caches and
// delegates data fetching to the Source.
type Portal struct {
	src     Source
	posture *Cache[PostureSnapshot]
	fw      *Cache[FrameworksSnapshot]
	uptime  *Cache[UptimeSnapshot]
}

// NewPortal creates a Portal with the given Source. Uses the default
// cache TTLs (60s for posture and frameworks, 1h for uptime).
func NewPortal(src Source) *Portal {
	return &Portal{
		src:     src,
		posture: NewCache[PostureSnapshot](DefaultPostureTTL),
		fw:      NewCache[FrameworksSnapshot](DefaultFrameworksTTL),
		uptime:  NewCache[UptimeSnapshot](DefaultUptimeTTL),
	}
}

// ServeHTTP implements http.Handler. Routes on the /trust prefix.
// No authentication is required. The 4 routes are:
//
//	GET /trust                  -> HTML page
//	GET /trust/                 -> HTML page (trailing slash)
//	GET /trust/api/posture      -> PostureSnapshot JSON
//	GET /trust/api/frameworks   -> FrameworksSnapshot JSON
//	GET /trust/api/uptime       -> UptimeSnapshot JSON
//	anything else               -> 404
func (p *Portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "trust portal is GET-only")
		return
	}
	path := r.URL.Path
	// Strip the /trust prefix.
	const prefix = "/trust"
	if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
		path = path[len(prefix):]
	}
	if path == "" || path == "/" {
		path = "/index"
	}
	switch path {
	case "/index", "/index.html":
		p.serveIndex(w, r)
	case "/api/posture":
		p.servePosture(w, r)
	case "/api/frameworks":
		p.serveFrameworks(w, r)
	case "/api/uptime":
		p.serveUptime(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveIndex serves the trust portal HTML page. The HTML is
// embedded as a string constant in the package so the page is
// served from the binary (no static file server, no CDN).
func (p *Portal) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Cache-Control: the page is meant to be polled and refreshed
	// by the browser. No caching is appropriate (the in-page JS
	// polls the JSON endpoints every 60s).
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(indexHTML))
}

// servePosture handles GET /trust/api/posture. Returns the cached
// PostureSnapshot, refreshing the cache on miss. The 60s cache
// means the underlying posture check runs at most once per minute
// regardless of how many browsers are polling.
func (p *Portal) servePosture(w http.ResponseWriter, r *http.Request) {
	if cached, ok := p.posture.Get(); ok {
		writeJSON(w, http.StatusOK, cached)
		return
	}
	snap, err := p.src.Posture()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "posture unavailable: "+err.Error())
		return
	}
	p.posture.Set(*snap)
	writeJSON(w, http.StatusOK, snap)
}

// serveFrameworks handles GET /trust/api/frameworks. Returns the
// cached FrameworksSnapshot, refreshing the cache on miss.
func (p *Portal) serveFrameworks(w http.ResponseWriter, r *http.Request) {
	if cached, ok := p.fw.Get(); ok {
		writeJSON(w, http.StatusOK, cached)
		return
	}
	snap, err := p.src.Frameworks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "frameworks unavailable: "+err.Error())
		return
	}
	p.fw.Set(*snap)
	writeJSON(w, http.StatusOK, snap)
}

// serveUptime handles GET /trust/api/uptime. Returns the cached
// UptimeSnapshot, refreshing the cache on miss. 1h cache.
func (p *Portal) serveUptime(w http.ResponseWriter, r *http.Request) {
	if cached, ok := p.uptime.Get(); ok {
		writeJSON(w, http.StatusOK, cached)
		return
	}
	snap, err := p.src.Uptime()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "uptime unavailable: "+err.Error())
		return
	}
	p.uptime.Set(*snap)
	writeJSON(w, http.StatusOK, snap)
}

// InvalidateCaches clears all 3 caches. Useful after a configuration
// change or in tests. Not part of the HTTP surface; callers must
// invoke it directly.
func (p *Portal) InvalidateCaches() {
	p.posture.Invalidate()
	p.fw.Invalidate()
	p.uptime.Invalidate()
}

// writeJSON writes a 200-class JSON response.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
