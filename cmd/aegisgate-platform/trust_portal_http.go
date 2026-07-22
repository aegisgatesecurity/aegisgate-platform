// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Trust Portal HTTP wire (v3.x close-out, Work Item 12)
// =========================================================================
//
// trust_portal_http.go wires the public, no-auth trust portal into
// the main binary at GET /trust and GET /trust/api/{posture,frameworks,uptime}.
//
// This is the customer-facing trust page at aegisgatesecurity.io/trust
// (per the v3.x close-out plan). Unlike every other v3.4.0+ feature
// HTTP route, the /trust/* routes have NO auth middleware - this is
// a public marketing/operational page.
//
// Design decisions (locked in plans/TRUST-PORTAL-DESIGN.md):
//   - Path: aegisgatesecurity.io/trust (not subdomain)
//   - Refresh: 60s (driven by 60s in-memory cache on the JSON endpoints)
//   - No customer count display (deferred to v3.5.0)
//   - Contact: support@aegisgatesecurity.io (already configured)
//
// The wire function follows the same pattern as wirePostureHandlers /
// wireAttestationHandlers: one package-level var for the source, the
// wire function constructs the data source and mounts the routes.
// =========================================================================

package main

import (
	"log"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trustportal"
)

// trustPortalSource is the runtime Source implementation for the
// trust portal. It builds the wire-format snapshots on demand and
// caches them via the 60s in-memory cache in pkg/trustportal.Portal.
//
// The source is a thin adapter: the platform's version/commit/mode/
// startTime are package-level vars in main, and the trust portal
// reads them directly. This is the same pattern as the posture
// HTTP handlers (posture_http.go) and the health endpoint.
type trustPortalSource struct{}

// Posture returns the current posture snapshot. The trust portal
// is a marketing/operational page; v1 returns a minimal "platform
// is up" snapshot. A full integration with the posture checker
// (which evaluates license, compliance, scanner, etc.) is a v2
// follow-up that can be done without changing the wire format.
func (s *trustPortalSource) Posture() (*trustportal.PostureSnapshot, error) {
	overall := "healthy"
	uptime := trustPortalUptimeString()
	return &trustportal.PostureSnapshot{
		GeneratedAt: time.Now(),
		Version:     version,
		Commit:      commit,
		Mode:        *mode,
		Overall:     overall,
		Uptime:      uptime,
		License: trustportal.LicenseInfo{
			Tier:        "professional",
			DisplayName: "Professional",
			Valid:       true,
			Message:     "AegisGate platform is running. See the trust page for live status.",
		},
	}, nil
}

// Frameworks returns the current frameworks snapshot. Uses the
// canonical module requirement table (deterministic, sorted).
func (s *trustPortalSource) Frameworks() (*trustportal.FrameworksSnapshot, error) {
	snap := trustportal.BuildFrameworksSnapshot()
	return &snap, nil
}

// Uptime returns the current uptime snapshot.
func (s *trustPortalSource) Uptime() (*trustportal.UptimeSnapshot, error) {
	snap := trustportal.BuildUptimeSnapshot(trustPortalUptimeString())
	return &snap, nil
}

// wireTrustPortalHandlers registers the /trust/* HTTP routes. Call
// this from main() after the platform's version, commit, mode, and
// start time are known. The wire function constructs the data
// source and mounts the Portal handler with no auth middleware
// (the trust portal is a public page).
func wireTrustPortalHandlers(mux *http.ServeMux) {
	portal := trustportal.NewPortal(&trustPortalSource{})
	// Mount on both /trust and /trust/ so the page works whether
	// the user navigates to either URL. The Portal handler
	// strips the /trust prefix internally.
	mux.Handle("/trust", portal)
	mux.Handle("/trust/", portal)
	log.Printf("[TRUST-PORTAL] Public trust portal enabled at /trust (HTML) and /trust/api/{posture,frameworks,uptime} (JSON, 60s cache)")
}

// trustPortalUptimeString formats the platform's start time into
// the "Nd Nh Nm Ns" format that pkg/trustportal's uptime parser
// understands. For v1, the trust portal only tracks process
// uptime (since the binary started). A 90-day uptime metric
// requires persistent uptime samples and is deferred to v3.5.0+.
func trustPortalUptimeString() string {
	if startTime.IsZero() {
		return "unknown"
	}
	d := time.Since(startTime)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if days > 0 {
		return formatTokens(days, "d") + " " + formatTokens(hours, "h") + " " + formatTokens(minutes, "m")
	}
	if hours > 0 {
		return formatTokens(hours, "h") + " " + formatTokens(minutes, "m") + " " + formatTokens(seconds, "s")
	}
	if minutes > 0 {
		return formatTokens(minutes, "m") + " " + formatTokens(seconds, "s")
	}
	return formatTokens(seconds, "s")
}

// formatTokens formats a non-negative integer with a single
// trailing unit suffix. Returns "0s" for 0.
func formatTokens(n int, unit string) string {
	if n == 0 {
		return "0s"
	}
	return itoa(n) + unit
}

// itoa is a small, allocation-free integer-to-string helper.
// Avoids pulling in strconv just for this.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
