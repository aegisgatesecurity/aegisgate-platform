// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CVE Entry feed (TODO-305)
//
// feed.go is the JSON feed of CVE entries consumed by
// the future static portal at cve.aegisgatesecurity.io.
// A Feed is a list of envelopes (possibly multiple per
// CVE-ID for the published-then-withdrawn-then-
// republished history). Consumers dedupe by CVE-ID and
// keep the latest entry.
//
// The Feed is the on-disk format for the portal:
//   - Each entry is a full attestation.Envelope (with
//     the CVEEntry in RawPayload).
//   - The feed can be large; it's typically read once
//     at portal build time.
//   - New entries are appended; existing entries are
//     not modified (immutability).
//
// Wire format: the Feed is a JSON object with a "version"
// field, a "generated_at" field, and an "entries" array.
// The "version" field allows future schema migrations.
//
// Example:
//   {
//     "version": 1,
//     "generated_at": "2026-06-18T12:00:00Z",
//     "entries": [<envelope>, <envelope>, ...]
//   }

package cve

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
)

// =====================================================================
// Feed
// =====================================================================

// FeedVersion is the current wire-format version of the
// feed. Bump this when making a breaking change to the
// schema (consumers should refuse to read feeds with a
// higher version number).
const FeedVersion = 1

// Feed is a JSON feed of CVE entry envelopes. The
// entries are NOT sorted or deduplicated here; that's
// the consumer's job.
type Feed struct {
	// Version is the feed schema version. Always
	// FeedVersion for v0.1.
	Version int `json:"version"`
	// GeneratedAt is the time the feed was last
	// generated. Set by the publisher; consumers can
	// use it for caching.
	GeneratedAt time.Time `json:"generated_at"`
	// Entries is the list of envelopes.
	Entries []*attestation.Envelope `json:"entries"`
}

// NewFeed returns an empty feed with the current
// version and the current UTC time.
func NewFeed() *Feed {
	return &Feed{
		Version:     FeedVersion,
		GeneratedAt: time.Now().UTC(),
		Entries:     []*attestation.Envelope{},
	}
}

// AppendEntry appends an envelope to the feed. The
// envelope is NOT validated here (the publisher
// already validated it). Duplicates are allowed (the
// consumer dedupes by CVE-ID).
func (f *Feed) AppendEntry(env *attestation.Envelope) error {
	if env == nil {
		return fmt.Errorf("cve: feed: AppendEntry: envelope is nil")
	}
	if f.Entries == nil {
		f.Entries = []*attestation.Envelope{}
	}
	f.Entries = append(f.Entries, env)
	f.GeneratedAt = time.Now().UTC()
	return nil
}

// Len returns the number of entries in the feed.
func (f *Feed) Len() int {
	if f == nil {
		return 0
	}
	return len(f.Entries)
}

// LatestByCVEID returns the latest envelope for the
// given CVE-ID. "Latest" means the envelope with the
// highest PublishedAt (or WithdrawnAt, for withdrawals
// with no PublishedAt). Returns nil if no matching
// envelope is found.
//
// This is the consumer-side helper for the
// "dedupe by CVE-ID, keep the latest" pattern. The
// portal uses this to build the CVE detail page.
func (f *Feed) LatestByCVEID(cveID string) *attestation.Envelope {
	if f == nil {
		return nil
	}
	var latest *attestation.Envelope
	var latestTime time.Time
	for _, env := range f.Entries {
		// Extract the CVE-ID from the subject.
		id := extractCVEIDFromSubject(env.Subject)
		if id != cveID {
			continue
		}
		// Decode the entry to get PublishedAt /
		// WithdrawnAt.
		entry, err := ParseEntry([]byte(env.RawPayload))
		if err != nil {
			// Skip malformed entries; the verify
			// path will reject them anyway.
			continue
		}
		// "Latest" = highest of (PublishedAt,
		// WithdrawnAt). A withdrawal with no
		// PublishedAt uses WithdrawnAt.
		var t time.Time
		if !entry.PublishedAt.IsZero() {
			t = entry.PublishedAt
		}
		if !entry.WithdrawnAt.IsZero() && entry.WithdrawnAt.After(t) {
			t = entry.WithdrawnAt
		}
		if latest == nil || t.After(latestTime) {
			latest = env
			latestTime = t
		}
	}
	return latest
}

// AllByCVEID returns all envelopes for the given
// CVE-ID, sorted by PublishedAt (then WithdrawnAt)
// ascending. Returns nil if no matching envelope is
// found.
//
// Envelopes with malformed payloads are skipped (they
// will be rejected by Verify anyway; surfacing them
// here would let the portal render garbage).
func (f *Feed) AllByCVEID(cveID string) []*attestation.Envelope {
	if f == nil {
		return nil
	}
	var matches []*attestation.Envelope
	for _, env := range f.Entries {
		if extractCVEIDFromSubject(env.Subject) != cveID {
			continue
		}
		// Skip malformed entries (matches the
		// LatestByCVEID behavior).
		if _, err := ParseEntry([]byte(env.RawPayload)); err != nil {
			continue
		}
		matches = append(matches, env)
	}
	if len(matches) == 0 {
		return nil
	}
	// Sort by the entry's "best" timestamp ascending.
	// Use PublishedAt if set, else WithdrawnAt.
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			ti := entryTime(matches[i])
			tj := entryTime(matches[j])
			if tj.Before(ti) {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}
	return matches
}

// entryTime returns the "best" timestamp for a
// CVE entry envelope: PublishedAt if set, else
// WithdrawnAt. Used for sorting.
func entryTime(env *attestation.Envelope) time.Time {
	entry, err := ParseEntry([]byte(env.RawPayload))
	if err != nil {
		return time.Time{}
	}
	if !entry.PublishedAt.IsZero() {
		return entry.PublishedAt
	}
	return entry.WithdrawnAt
}

// WriteJSON serializes the feed to JSON. Pretty-
// printed for human readability of the static portal
// source.
func (f *Feed) WriteJSON() ([]byte, error) {
	return json.MarshalIndent(f, "", "  ")
}

// WriteJSONFile writes the feed to a file. Creates
// parent directories as needed.
func (f *Feed) WriteJSONFile(path string) error {
	data, err := f.WriteJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ReadJSONFile reads a feed from a file.
func ReadJSONFile(path string) (*Feed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ReadJSON(data)
}

// ReadJSON parses a feed from JSON bytes.
func ReadJSON(data []byte) (*Feed, error) {
	var f Feed
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("cve: feed: parse: %w", err)
	}
	if f.Version > FeedVersion {
		return nil, fmt.Errorf("cve: feed: version %d is higher than supported %d", f.Version, FeedVersion)
	}
	if f.Version < 1 {
		// Default to 1 for missing/zero.
		f.Version = FeedVersion
	}
	return &f, nil
}
