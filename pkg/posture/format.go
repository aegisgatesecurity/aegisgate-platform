// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Posture Check (v3.3.0 Phase 6.5)
//
// format.go renders a posture.Report as plain text (the default mode
// for the aegisgate status CLI) or as JSON (the verbose mode and the
// HTTP API). The plain-text format is designed to be readable by a
// non-technical operator per the original Padlock spec constraint 17.
//
// v3.3.0 Phase 6.5.

package posture

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// emojiForStatus returns the on-screen indicator for a HealthStatus.
func emojiForStatus(s HealthStatus) string {
	switch s {
	case StatusHealthy:
		return "✅"
	case StatusDegraded:
		return "⚠️"
	case StatusUnhealthy:
		return "❌"
	case StatusUnknown:
		return "❔"
	default:
		return "•"
	}
}

// nl is a newline constant. We use a Go raw string containing a single
// newline character so that we never need to embed a backslash-n in a
// string literal (which is fragile in some code-generation tools).
const nl = `
`

// FormatText renders a Report as a multi-line, plain-text summary
// suitable for the aegisgate-status CLI output. The format is locked
// in V3.3.0-ROADMAP §6.5. The overall status appears on the first
// line for at-a-glance scanning; subsystem details follow.
func FormatText(r *Report) string {
	if r == nil {
		return "AegisGate posture: <no data>" + nl
	}

	var b strings.Builder

	fmt.Fprintf(&b, "AegisGate is %s %s%s", strings.ToLower(string(r.Overall)), emojiForStatus(r.Overall), nl)

	versionLine := r.Version
	if versionLine == "" {
		versionLine = "<unknown version>"
	}
	modeLine := ""
	if r.Mode != "" {
		modeLine = fmt.Sprintf(" [%s mode]", r.Mode)
	}
	fmt.Fprintf(&b, "  Version:        %s (commit: %s)%s%s", versionLine, emptyAsUnknown(r.Commit), modeLine, nl)

	if r.Uptime != "" {
		fmt.Fprintf(&b, "  Uptime:         %s%s", r.Uptime, nl)
	}

	if r.License != nil {
		fmt.Fprintf(&b, "  Tier:           %s (%s)%s", r.License.Tier, r.License.DisplayName, nl)
		if r.License.Valid {
			if r.License.Customer != "" {
				fmt.Fprintf(&b, "  Customer:       %s%s", r.License.Customer, nl)
			}
			if !r.License.ExpiresAt.IsZero() {
				fmt.Fprintf(&b, "  Expires:        %s%s", r.License.ExpiresAt.Format(time.RFC3339), nl)
			}
			fmt.Fprintf(&b, "  Modules:        %s%s", moduleList(r.License.ModulesOwned), nl)
		} else {
			fmt.Fprintf(&b, "  License:        invalid (%s)%s", r.License.Message, nl)
		}
	}

	if len(r.Subsystems) > 0 {
		b.WriteString("  Subsystems:" + nl)
		for _, s := range r.Subsystems {
			fmt.Fprintf(&b, "    %s %-14s %s%s", emojiForStatus(s.Status), s.Name+":", s.Summary, nl)
		}
	}

	if len(r.Compliance) > 0 {
		b.WriteString("  Compliance:" + nl)
		for _, c := range r.Compliance {
			marker := "○"
			if c.Enforced {
				marker = "●"
			}
			impl := ""
			if c.Enforced && !c.HasImplementation {
				impl = " (no implementation)"
			}
			fmt.Fprintf(&b, "    %s %-12s required=%s enforced=%v%s%s",
				marker, c.DisplayName, c.RequiredTier, c.Enforced, impl, nl)
		}
	}

	if r.Overall == StatusUnhealthy || r.Overall == StatusDegraded {
		b.WriteString("  Action required. Run aegisgate status --verbose for details." + nl)
	}

	return b.String()
}

// FormatVerboseText renders a Report with extra detail.
func FormatVerboseText(r *Report) string {
	if r == nil {
		return FormatText(nil)
	}
	var b strings.Builder
	b.WriteString(FormatText(r))

	fmt.Fprintf(&b, "%s  Generated at:   %s%s", nl, r.GeneratedAt.Format(time.RFC3339Nano), nl)

	if r.License != nil && r.License.Message != "" {
		fmt.Fprintf(&b, "  License msg:   %s%s", r.License.Message, nl)
	}

	if len(r.Compliance) > 0 {
		b.WriteString("  Compliance detail:" + nl)
		for _, c := range r.Compliance {
			fmt.Fprintf(&b, "    %-12s framework=%s required_tier=%s enforced=%v impl=%v reason=%s%s",
				c.DisplayName, c.Framework, c.RequiredTier, c.Enforced, c.HasImplementation, c.Reason, nl)
		}
	}

	return b.String()
}

// FormatJSON serializes a Report as indented JSON.
func FormatJSON(r *Report) ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.MarshalIndent(r, "", "  ")
}

// moduleList renders a []string as a human-friendly list.
func moduleList(modules []string) string {
	if len(modules) == 0 {
		return "none"
	}
	return strings.Join(modules, ", ")
}

// emptyAsUnknown returns the input string, or "<unknown>" if empty.
func emptyAsUnknown(s string) string {
	if s == "" {
		return "<unknown>"
	}
	return s
}
