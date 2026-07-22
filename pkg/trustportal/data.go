// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Trust Portal: data adapters
// =========================================================================
//
// data.go provides read-only adapters over the existing AegisGate
// subsystems (pkg/posture, pkg/compliance) so the trust portal
// HTTP handlers don't need to know about those subsystems'
// internals. The adapters return the trust portal's wire format
// directly, with no internal field names exposed.
//
// The wire format is intentionally simple and stable: any change
// here is a breaking change for the public trust portal HTML page
// (which polls these endpoints every 60s). Add new fields with care;
// never rename or remove existing ones without a deprecation plan.
// =========================================================================

package trustportal

import (
	"sort"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/mapping"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/posture"
)

// PostureSnapshot is the wire format for /trust/api/posture. It is
// a flat summary of the platform's posture, suitable for direct
// rendering in the trust portal HTML page.
type PostureSnapshot struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Version     string      `json:"version"`
	Commit      string      `json:"commit,omitempty"`
	Mode        string      `json:"mode,omitempty"`
	Overall     string      `json:"overall_status"`
	Uptime      string      `json:"uptime,omitempty"`
	License     LicenseInfo `json:"license"`
	Subsystems  []SubInfo   `json:"subsystems"`
}

// LicenseInfo is the license block of the posture snapshot. Only
// fields safe to expose publicly are included (no license key, no
// customer email, no internal IDs).
type LicenseInfo struct {
	Tier        string    `json:"tier"`
	DisplayName string    `json:"display_name"`
	Valid       bool      `json:"valid"`
	GracePeriod bool      `json:"grace_period,omitempty"`
	Expired     bool      `json:"expired,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Message     string    `json:"message,omitempty"`
}

// SubInfo is the per-subsystem health entry in the posture snapshot.
type SubInfo struct {
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
}

// FrameworkInfo is the per-framework entry in /trust/api/frameworks.
// "Tier1" is a boolean indicating whether the framework is at full
// in-scope Tier 1 coverage (the v3.x close-out definition).
type FrameworkInfo struct {
	Key               string `json:"key"`
	DisplayName       string `json:"display_name"`
	Tier1             bool   `json:"tier1"`
	HasImplementation bool   `json:"has_implementation"`
	Enforced          bool   `json:"enforced"`
	RequiredTier      string `json:"required_tier,omitempty"`
	ControlCount      int    `json:"control_count"`
}

// FrameworksSnapshot is the wire format for /trust/api/frameworks.
type FrameworksSnapshot struct {
	GeneratedAt time.Time       `json:"generated_at"`
	TotalCount  int             `json:"total_count"`
	Tier1Count  int             `json:"tier1_count"`
	Frameworks  []FrameworkInfo `json:"frameworks"`
}

// UptimeSnapshot is the wire format for /trust/api/uptime. The
// uptime percentage is computed over the last 90 days. The 1h
// cache means the value is up to 1 hour stale; this is acceptable
// for a public trust badge.
//
// v1: AegisGate's posture.Report does not track historical uptime
// (only current process uptime). For v1, we report the current
// process uptime and a "since last restart" badge. A real 90-day
// uptime metric requires the platform to write uptime samples to
// disk (out of scope for v3.x close-out).
type UptimeSnapshot struct {
	GeneratedAt     time.Time `json:"generated_at"`
	ProcessUptime   string    `json:"process_uptime"`
	UptimeBadge     string    `json:"uptime_badge"`
	BadgeDisclaimer string    `json:"badge_disclaimer"`
}

// BuildPostureSnapshot converts a posture.Report into the trust
// portal's PostureSnapshot wire format. Only publicly-safe fields
// are included. The function is pure (no I/O); the caller is
// responsible for caching.
func BuildPostureSnapshot(r *posture.Report) PostureSnapshot {
	snap := PostureSnapshot{
		GeneratedAt: r.GeneratedAt,
		Version:     r.Version,
		Commit:      r.Commit,
		Mode:        r.Mode,
		Overall:     string(r.Overall),
		Uptime:      r.Uptime,
	}
	if r.License != nil {
		snap.License = LicenseInfo{
			Tier:        r.License.Tier,
			DisplayName: r.License.DisplayName,
			Valid:       r.License.Valid,
			GracePeriod: r.License.GracePeriod,
			Expired:     r.License.Expired,
			ExpiresAt:   r.License.ExpiresAt,
			Message:     r.License.Message,
		}
	}
	for _, sub := range r.Subsystems {
		snap.Subsystems = append(snap.Subsystems, SubInfo{
			Name:    sub.Name,
			Status:  string(sub.Status),
			Summary: sub.Summary,
			Details: sub.Details,
		})
	}
	return snap
}

// BuildFrameworksSnapshot builds the FrameworksSnapshot from the
// canonical module requirement table (compliance.AllModuleRequirements).
// The Tier1 flag is set when the framework has HasImplementation=true
// (i.e., the v3.x close-out "Tier 1" definition: a real module that
// evaluates controls, not just a framework name in the map).
//
// The mapping's framework name display is preferred (e.g., "SOC 2
// Type II") over the module's DisplayName, because the mapping is
// curated for the customer-facing trust portal.
//
// We use AllModuleRequirements rather than Manager.GetActiveFrameworks
// because:
//   - AllModuleRequirements is a deterministic, sorted table
//     (the Manager's GetActiveFrameworks iterates a Go map, so the
//     order is random across runs - the trust portal page would
//     flicker if the order changed on every refresh).
//   - AllModuleRequirements includes HasImplementation and
//     RequiredTier, which Manager.GetActiveFrameworks does not
//     (the Framework interface is runtime-only).
//   - The trust portal is a static view of "what frameworks do
//     we support" - it doesn't need to reflect runtime state
//     (e.g., a framework disabled by a config flag). The
//     canonical table is the right level of abstraction.
func BuildFrameworksSnapshot() FrameworksSnapshot {
	snap := FrameworksSnapshot{
		GeneratedAt: time.Now(),
	}
	for _, req := range compliance.AllModuleRequirements() {
		// Use the module's canonical key (e.g., "hipaa") as the
		// JSON key. The mapping's FrameworkName map uses the same
		// key, so we get a clean handoff.
		//
		// Two modules have key mismatches between the license
		// package (which names the billable module) and the
		// mapping package (which uses the canonical framework
		// key). We translate them here so the trust portal
		// shows the same display name as the rest of the
		// platform's compliance reporting.
		//   - license.ModuleISO42001 = "iso42001" -> mapping's "iso_42001"
		//   - license.ModuleFIPS     = "fips"     -> mapping's "fips_140"
		key := trustPortalKey(req.Module)
		info := FrameworkInfo{
			Key:               key,
			DisplayName:       mapping.FrameworkName[key],
			HasImplementation: req.HasImplementation,
			RequiredTier:      req.RequiredTier.String(),
		}
		if info.DisplayName == "" {
			info.DisplayName = req.DisplayName
		}
		// Tier 1 = has a real implementation. This matches the
		// v3.x close-out definition (a real module that evaluates
		// controls, not a placeholder).
		if info.HasImplementation {
			info.Tier1 = true
			snap.Tier1Count++
		}
		snap.Frameworks = append(snap.Frameworks, info)
	}
	// Sort alphabetically by DisplayName for deterministic output.
	// The marketing audience expects frameworks in a predictable
	// alphabetical order, not the tier-grouped order that
	// AllModuleRequirements returns. Ties (same DisplayName) are
	// broken by Key for full determinism (Go's sort.Slice is not
	// stable, and we want the same order on every run).
	sort.Slice(snap.Frameworks, func(i, j int) bool {
		if snap.Frameworks[i].DisplayName != snap.Frameworks[j].DisplayName {
			return snap.Frameworks[i].DisplayName < snap.Frameworks[j].DisplayName
		}
		return snap.Frameworks[i].Key < snap.Frameworks[j].Key
	})
	snap.TotalCount = len(snap.Frameworks)
	return snap
}

// BuildUptimeSnapshot builds the UptimeSnapshot from the process
// uptime string (as formatted by pkg/posture, e.g., "3d 4h 12m").
// v1 only tracks process uptime (since last restart). A 90-day
// uptime metric requires persistent uptime samples (deferred to
// v3.5.0+).
//
// The badge is "good" if process uptime > 24h, "fair" if 1-24h,
// "new" if < 1h. These thresholds match the Vanta/Drata convention
// for "maturity" badges.
//
// We accept the uptime string rather than *posture.Report to keep
// this package free of a hard dependency on pkg/posture (the wire
// function in cmd/aegisgate-platform can pass the string in).
func BuildUptimeSnapshot(processUptime string) UptimeSnapshot {
	snap := UptimeSnapshot{
		GeneratedAt:   time.Now(),
		ProcessUptime: processUptime,
	}
	// Parse the uptime string (e.g., "3d 4h 12m", "12m 5s", "45s")
	// into a time.Duration. If parsing fails, the badge is "unknown".
	dur, err := parseUptimeDuration(processUptime)
	if err == nil {
		switch {
		case dur >= 24*time.Hour:
			snap.UptimeBadge = "good"
		case dur >= 1*time.Hour:
			snap.UptimeBadge = "fair"
		case dur > 0:
			snap.UptimeBadge = "new"
		default:
			snap.UptimeBadge = "unknown"
		}
	} else {
		snap.UptimeBadge = "unknown"
	}
	// The badge is a process-uptime badge, not a 90-day SLA
	// metric. Disclose this so prospects don't misread it.
	snap.BadgeDisclaimer = "Process uptime since last restart. A 90-day SLA badge is planned for v3.5.0."
	return snap
}

// parseUptimeDuration parses the posture package's uptime format
// (e.g., "3d 4h 12m", "12m 5s", "45s") into a time.Duration.
// Returns an error if the string is empty or has no recognized
// tokens.
func parseUptimeDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errEmptyUptime
	}
	// The format is "Nd Nh Nm Ns" with spaces between tokens.
	// We use a simple state machine: accumulate days, hours,
	// minutes, seconds.
	var d time.Duration
	var days, hours, minutes, seconds int
	var sawAny bool
	// Manual parser to avoid pulling in time.ParseDuration (which
	// doesn't support "d" for days, only "h" for hours).
	// Format: "[Nd ][Nh ][Nm ][Ns]" - each token is optional.
	tokens := splitUptimeTokens(s)
	for _, tok := range tokens {
		if len(tok) < 2 {
			continue
		}
		numStr := tok[:len(tok)-1]
		unit := tok[len(tok)-1]
		var n int
		for _, ch := range numStr {
			if ch < '0' || ch > '9' {
				continue
			}
			n = n*10 + int(ch-'0')
		}
		switch unit {
		case 'd':
			days += n
			sawAny = true
		case 'h':
			hours += n
			sawAny = true
		case 'm':
			minutes += n
			sawAny = true
		case 's':
			seconds += n
			sawAny = true
		}
	}
	if !sawAny {
		return 0, errEmptyUptime
	}
	d = time.Duration(days)*24*time.Hour +
		time.Duration(hours)*time.Hour +
		time.Duration(minutes)*time.Minute +
		time.Duration(seconds)*time.Second
	return d, nil
}

// splitUptimeTokens splits the uptime string into tokens by
// whitespace. Used by parseUptimeDuration.
func splitUptimeTokens(s string) []string {
	var tokens []string
	var cur []byte
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if len(cur) > 0 {
				tokens = append(tokens, string(cur))
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, s[i])
	}
	if len(cur) > 0 {
		tokens = append(tokens, string(cur))
	}
	return tokens
}

// errEmptyUptime is the sentinel for an unparseable uptime string.
var errEmptyUptime = &uptimeParseError{msg: "empty or unparseable uptime string"}

// uptimeParseError is the error type for parseUptimeDuration.
type uptimeParseError struct{ msg string }

func (e *uptimeParseError) Error() string { return e.msg }

// trustPortalKey normalizes a license module key to the trust
// portal's canonical framework key (the one used by
// pkg/compliance/mapping's FrameworkName map). Two modules have
// name mismatches between the license package and the mapping
// package; this function translates them.
//
// If the input is not in the translation table, it is returned
// unchanged (so adding a new module to the license package
// without adding it to this map is a soft fallback - the
// display name lookup will use the module's DisplayName as a
// fallback in BuildFrameworksSnapshot).
func trustPortalKey(licenseKey string) string {
	switch licenseKey {
	case "iso42001":
		return "iso_42001"
	case "fips":
		return "fips_140"
	default:
		return licenseKey
	}
}
