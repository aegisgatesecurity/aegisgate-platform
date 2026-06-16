// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CVE Entry types (TODO-305)
//
// types.go defines the CVEEntry struct, the severity
// enum, the validation method, and the sentinel errors
// used by the verify path.
//
// The schema is adapted from CVE 5.0 JSON record format
// (https://github.com/CVEProject/cve-schema) but tuned
// for AI/ML vulnerabilities:
//   - Provider + model (e.g., openai/gpt-4-turbo) instead
//     of "vendor + product" (the CVE 5.0 fields still
//     work, but the AI-specific field is more readable).
//   - AffectedVersions is a list of semver-style strings
//     (e.g., "<2024-08-01", ">=2024-08-01 <2024-10-15").
//   - FixedVersions is a list of single-version strings
//     (e.g., "2024-10-15").
//   - Severity is a CVSS 3.1 base score (0.0-10.0) + a
//     vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/
//     UI:R/S:U/C:H/I:H/A:N").
//   - References is a list of URLs (advisories, papers,
//     upstream fixes, blog posts).
//   - Mitigations is a free-form list of mitigations
//     (the order is significant: most-recommended first).
//   - WithdrawnAt is optional; if set, the entry is a
//     withdrawal (consumers should treat the CVE-ID as
//     withdrawn even if a previous non-withdrawn entry
//     exists).

package cve

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// =====================================================================
// Constants
// =====================================================================

// AEGIS-YEAR-NNNN: AegisGate-disclosed vulnerability.
// Format:
//
//	AEGIS-<4-digit-year>-<4+ digit sequence number>
//
// The 4+ digit sequence is intentional: it allows more
// than 9999 disclosures per year if needed. We use a
// minimum of 4 digits (zero-padded) for sortability.
const cveIDPattern = `^AEGIS-(\d{4})-(\d{4,})$`

// cveIDRegexp is the compiled CVE-ID regex.
var cveIDRegexp = regexp.MustCompile(cveIDPattern)

// cveIDMaxLen is the maximum length of a CVE-ID. 30
// chars accommodates AEGIS-9999-9999999999 plus room.
const cveIDMaxLen = 30

// SubjectKind is the URI kind component for the envelope
// subject. Must match the registry in pkg/attestation.
const SubjectKind = "cve"

// MaxTitleLen, MaxDescriptionLen, etc. are the maximum
// string lengths for the user-supplied fields. These are
// generous limits; we don't want a defensive coder to
// truncate real CVE entries.
const (
	MaxTitleLen        = 500
	MaxDescriptionLen  = 10000
	MaxReferenceLen    = 2000
	MaxMitigationLen   = 2000
	MaxAffectedLen     = 200
	MaxFixedLen        = 200
	MaxProviderLen     = 200
	MaxDiscoveredByLen = 200
	MaxVectorLen       = 200
)

// =====================================================================
// Severity (CVSS 3.1)
// =====================================================================

// SeverityBand is a coarse-grained severity band, derived
// from the CVSS 3.1 base score. Consumers can use the
// numeric Score for fine-grained display, or the Band for
// the common "Low/Medium/High/Critical" UI.
type SeverityBand string

const (
	SeverityNone     SeverityBand = "NONE"
	SeverityLow      SeverityBand = "LOW"
	SeverityMedium   SeverityBand = "MEDIUM"
	SeverityHigh     SeverityBand = "HIGH"
	SeverityCritical SeverityBand = "CRITICAL"
)

// SeverityFromScore returns the severity band for a given
// CVSS 3.1 base score (0.0 - 10.0). Matches the standard
// CVSS 3.1 thresholds:
//
//	0.0       NONE
//	0.1-3.9   LOW
//	4.0-6.9   MEDIUM
//	7.0-8.9   HIGH
//	9.0-10.0  CRITICAL
func SeverityFromScore(score float64) SeverityBand {
	switch {
	case score <= 0:
		return SeverityNone
	case score < 4.0:
		return SeverityLow
	case score < 7.0:
		return SeverityMedium
	case score < 9.0:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

// =====================================================================
// CVEEntry
// =====================================================================

// CVEEntry is a single CVE record. A CVE-ID can have
// multiple CVEEntry instances over time (e.g., published
// then withdrawn then republished); the consumer
// deduplicates by CVE-ID and keeps the latest.
//
// Field semantics:
//
//   - ID is the CVE-ID (e.g., AEGIS-2026-0001). REQUIRED.
//   - Title is a one-line summary. REQUIRED.
//   - Description is a multi-paragraph explanation.
//     REQUIRED.
//   - Affected is a list of "<provider>/<model>@<version-
//     range>" strings (e.g., "anthropic/claude-3-5-
//     sonnet@<20241022"). OPTIONAL (empty list = unknown
//     at time of disclosure; can be filled in later via
//     a republished entry).
//   - Fixed is a list of "<provider>/<model>@<version>"
//     strings (e.g., "anthropic/claude-3-5-sonnet@
//     20241022"). OPTIONAL.
//   - Score is the CVSS 3.1 base score (0.0 - 10.0).
//     OPTIONAL (zero = not yet scored).
//   - Vector is the CVSS 3.1 vector string. OPTIONAL.
//   - Band is the severity band (derived from Score).
//     Set automatically by Validate() if Score is set.
//   - References is a list of URLs (advisories, papers,
//     blog posts). OPTIONAL.
//   - Mitigations is a free-form list of mitigations,
//     most-recommended first. OPTIONAL.
//   - DiscoveredBy is the name of the discoverer (e.g.,
//     "AegisGate Research", "Jane Doe @ Acme Corp").
//     REQUIRED.
//   - DisclosedAt is the time the vulnerability was
//     disclosed to the provider (NOT the public
//     disclosure time). REQUIRED.
//   - PublishedAt is the time the CVE was published.
//     Set automatically by Publish if zero.
//   - WithdrawnAt is the time the CVE was withdrawn.
//     If set, the entry is a withdrawal; consumers
//     should treat the CVE-ID as withdrawn.
type CVEEntry struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Affected     []string  `json:"affected,omitempty"`
	Fixed        []string  `json:"fixed,omitempty"`
	Score        float64   `json:"score,omitempty"`
	Vector       string    `json:"vector,omitempty"`
	Band         string    `json:"band,omitempty"`
	References   []string  `json:"references,omitempty"`
	Mitigations  []string  `json:"mitigations,omitempty"`
	DiscoveredBy string    `json:"discovered_by"`
	DisclosedAt  time.Time `json:"disclosed_at"`
	PublishedAt  time.Time `json:"published_at,omitempty"`
	WithdrawnAt  time.Time `json:"withdrawn_at,omitempty"`
}

// IsWithdrawal returns true if the entry is a withdrawal
// (i.e., WithdrawnAt is set and non-zero).
func (e *CVEEntry) IsWithdrawal() bool {
	return e != nil && !e.WithdrawnAt.IsZero()
}

// IsPublished returns true if the entry has been
// published (i.e., PublishedAt is set and non-zero).
func (e *CVEEntry) IsPublished() bool {
	return e != nil && !e.PublishedAt.IsZero()
}

// Validate checks that the entry is well-formed. It
// applies defaults where possible (e.g., Band is derived
// from Score) and returns an error on the first invalid
// field.
//
// The validation rules are:
//   - ID matches AEGIS-YYYY-NNNN and is <= 30 chars.
//   - Title is non-empty and <= MaxTitleLen.
//   - Description is non-empty and <= MaxDescriptionLen.
//   - Score is in [0.0, 10.0] if set.
//   - Vector is non-empty if Score is set, and is <=
//     MaxVectorLen.
//   - References are valid URLs (http or https).
//   - DiscoveredBy is non-empty and <= MaxDiscoveredByLen.
//   - DisclosedAt is set and non-zero.
//   - For withdrawals, WithdrawnAt is set and >=
//     DisclosedAt.
//
// On success, Band is populated if Score is set.
func (e *CVEEntry) Validate() error {
	if e == nil {
		return errors.New("cve: CVEEntry is nil")
	}
	// ID format.
	if len(e.ID) == 0 {
		return errors.New("cve: id is required")
	}
	if len(e.ID) > cveIDMaxLen {
		return fmt.Errorf("cve: id is too long (%d > %d): %q", len(e.ID), cveIDMaxLen, e.ID)
	}
	if !cveIDRegexp.MatchString(e.ID) {
		return fmt.Errorf("cve: id does not match AEGIS-YYYY-NNNN pattern: %q", e.ID)
	}
	// Title.
	if len(e.Title) == 0 {
		return errors.New("cve: title is required")
	}
	if len(e.Title) > MaxTitleLen {
		return fmt.Errorf("cve: title is too long (%d > %d)", len(e.Title), MaxTitleLen)
	}
	// Description.
	if len(e.Description) == 0 {
		return errors.New("cve: description is required")
	}
	if len(e.Description) > MaxDescriptionLen {
		return fmt.Errorf("cve: description is too long (%d > %d)", len(e.Description), MaxDescriptionLen)
	}
	// Score + vector.
	if e.Score < 0 || e.Score > 10 {
		return fmt.Errorf("cve: score is out of range [0, 10]: %v", e.Score)
	}
	if e.Score > 0 && e.Vector == "" {
		return errors.New("cve: vector is required when score is set")
	}
	if len(e.Vector) > MaxVectorLen {
		return fmt.Errorf("cve: vector is too long (%d > %d)", len(e.Vector), MaxVectorLen)
	}
	// Derive Band from Score if Score is set and Band
	// is empty. This auto-fills the band for the
	// publisher's convenience.
	if e.Score > 0 && e.Band == "" {
		e.Band = string(SeverityFromScore(e.Score))
	}
	// References: each must be a valid http/https URL.
	for i, ref := range e.References {
		if len(ref) > MaxReferenceLen {
			return fmt.Errorf("cve: reference[%d] is too long (%d > %d)", i, len(ref), MaxReferenceLen)
		}
		u, err := url.Parse(ref)
		if err != nil {
			return fmt.Errorf("cve: reference[%d] is not a valid URL: %v", i, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("cve: reference[%d] must be http or https, got %q", i, u.Scheme)
		}
	}
	// Mitigations: just length-check each.
	for i, m := range e.Mitigations {
		if len(m) > MaxMitigationLen {
			return fmt.Errorf("cve: mitigation[%d] is too long (%d > %d)", i, len(m), MaxMitigationLen)
		}
	}
	// Affected: just length-check each.
	for i, a := range e.Affected {
		if len(a) > MaxAffectedLen {
			return fmt.Errorf("cve: affected[%d] is too long (%d > %d)", i, len(a), MaxAffectedLen)
		}
	}
	// Fixed: just length-check each.
	for i, f := range e.Fixed {
		if len(f) > MaxFixedLen {
			return fmt.Errorf("cve: fixed[%d] is too long (%d > %d)", i, len(f), MaxFixedLen)
		}
	}
	// DiscoveredBy.
	if len(e.DiscoveredBy) == 0 {
		return errors.New("cve: discovered_by is required")
	}
	if len(e.DiscoveredBy) > MaxDiscoveredByLen {
		return fmt.Errorf("cve: discovered_by is too long (%d > %d)", len(e.DiscoveredBy), MaxDiscoveredByLen)
	}
	// DisclosedAt.
	if e.DisclosedAt.IsZero() {
		return errors.New("cve: disclosed_at is required")
	}
	// Withdrawals: WithdrawnAt must be set and >=
	// DisclosedAt.
	if !e.WithdrawnAt.IsZero() && e.WithdrawnAt.Before(e.DisclosedAt) {
		return fmt.Errorf("cve: withdrawn_at (%v) is before disclosed_at (%v)", e.WithdrawnAt, e.DisclosedAt)
	}
	return nil
}

// =====================================================================
// Sentinel errors
// =====================================================================

// ErrCVEIDMismatch is returned by Verify when the
// envelope's subject does not match the CVEEntry's ID.
var ErrCVEIDMismatch = errors.New("cve: envelope subject does not match CVE-ID")

// ErrCVEIssuerMismatch is returned by Verify when the
// envelope's issuer does not match the expected
// publisher (i.e., the issuer's prefix is not "cve:...").
var ErrCVEIssuerMismatch = errors.New("cve: envelope issuer is not a cve: publisher")

// ErrCVEExpired is reserved for future use. CVE entries
// have no expiration by default (TTL = 0), so this is
// never returned by v0.1 verify. Defined for forward
// compatibility with the future "time-bombed CVE"
// feature (e.g., embargoed disclosures that auto-publish
// after N days).
var ErrCVEExpired = errors.New("cve: envelope has expired")

// =====================================================================
// Helpers
// =====================================================================

// extractCVEIDFromSubject returns the CVE-ID portion of
// an envelope subject. The subject format is
// "aegisgate://cve/<cve-id>". Returns "" if the subject
// doesn't match.
func extractCVEIDFromSubject(subject string) string {
	const prefix = "aegisgate://cve/"
	if !strings.HasPrefix(subject, prefix) {
		return ""
	}
	return subject[len(prefix):]
}
