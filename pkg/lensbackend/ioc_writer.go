// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - IOC Writer
// =========================================================================
//
// ioc_writer.go aggregates validated Events into IOCs and writes
// them to the shared pkg/ioc.Store. This is the "closed-loop
// threat intel" half of the Lens: the data goes from a Lens
// installation, through the backend, into the IOC store, and
// out to the Gateway via the existing gossip protocol.
//
// Aggregation algorithm:
//
//   The aggregator maintains an in-memory map keyed by
//   SHA-256(category || "|" || pattern || "|" || domain_hash).
//   The map value is an ioc.IOC. On every incoming Event:
//
//     1. Compute the aggregation key from the event's
//        category, pattern (derived from category for v0.1),
//        and domain_hash.
//     2. If the key is not in the map, create a new ioc.IOC
//        with Type=IOCTypePIIDetected (or IOCTypeSecretLeak
//        for secret_api_key / source_code), Severity=event.Severity,
//        Count=1, FirstSeen=LastSeen=event.Timestamp.
//     3. If the key is in the map, increment Count, update
//        LastSeen, and take the WorseSeverity of the existing
//        and new severities.
//     4. Every 100 events (configurable), flush the in-memory
//        IOCs to the underlying ioc.Store. The store then takes
//        care of on-disk persistence, the existing gossip
//        protocol, and the existing STIX/TAXII export.
//
// Why a separate aggregator (not just Observe per event):
//
//   - One Lens event is one observation. An IOC is a pattern,
//     not a single observation. The aggregator's job is to
//     fold N events into a single IOC.
//   - The same (category, pattern, domain_hash) can be observed
//     by many users of the same Lens installation, or by users
//     of many Lens installations pointing at the same backend.
//     Both should aggregate to one IOC.
//   - The aggregation key includes domain_hash, so the same
//     pattern in ChatGPT and in Claude are different IOCs
//     (different surfaces; different mitigation strategies).
//
// Fingerprint:
//
//   The IOC's Fingerprint is set to the aggregation key. The
//   fingerprint input is:
//
//     SHA-256(category + "|" + pattern + "|" + domain_hash)
//
//   This is consistent with pkg/ioc.fingerprint.Fingerprint
//   but we hand-roll it here to avoid coupling the Lens
//   aggregator to the IOC library's internal types. The
//   output (a 64-character lowercase hex string) is identical
//   to what pkg/ioc produces.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// iocWriter is the aggregator + writer.
type iocWriter struct {
	mu      sync.Mutex
	store   *ioc.Store
	pending map[string]*ioc.IOC // aggregation key -> in-flight IOC
	flushN  int                 // number of events between flushes
	count   int                 // number of events since last flush
}

// newIOCWriter creates an iocWriter that aggregates Events into
// the given ioc.Store, flushing every flushN events. A flushN
// of 100 is a reasonable default; it bounds the in-memory
// pending map to ~100 entries under typical load.
func newIOCWriter(store *ioc.Store, flushN int) *iocWriter {
	if flushN < 1 {
		flushN = 100
	}
	return &iocWriter{
		store:   store,
		pending: make(map[string]*ioc.IOC),
		flushN:  flushN,
	}
}

// add aggregates an Event into the pending map. If the pending
// map reaches flushN entries, the writer flushes to the IOC
// store. Safe to call from multiple goroutines.
func (w *iocWriter) add(ctx context.Context, e Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := aggregationKey(e.Category, e.DomainHash)
	stored, ok := w.pending[key]
	if !ok {
		// New IOC. Create it.
		stored = &ioc.IOC{
			Fingerprint:     key,
			Type:            categoryToIOCType(e.Category),
			Severity:        severityToIOC(e.Severity),
			Source:          "lens",
			Category:        e.Category,
			Pattern:         patternFromCategory(e.Category),
			SourceProvider:  sourceProviderFromDomainHash(e.DomainHash),
			AffectsLens:     true,
			AffectsGateway:  true,
			FirstSeen:       time.Unix(e.Timestamp, 0).UTC(),
			LastSeen:        time.Unix(e.Timestamp, 0).UTC(),
			Count:           1,
		}
		w.pending[key] = stored
	} else {
		// Update existing.
		stored.Count++
		ts := time.Unix(e.Timestamp, 0).UTC()
		if ts.After(stored.LastSeen) {
			stored.LastSeen = ts
		}
		stored.Severity = ioc.WorseSeverity(stored.Severity, severityToIOC(e.Severity))
	}

	w.count++
	if w.count >= w.flushN {
		return w.flushLocked(ctx)
	}
	return nil
}

// flush forces a flush of all pending IOCs to the underlying
// store. Safe to call from multiple goroutines.
func (w *iocWriter) flush(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked(ctx)
}

// flushLocked is the inner flush; caller must hold w.mu.
func (w *iocWriter) flushLocked(ctx context.Context) error {
	for _, stored := range w.pending {
		// Copy the IOC; Observe takes ownership of the value
		// and may modify the in-memory state.
		copy := *stored
		if _, err := w.store.Observe(copy); err != nil {
			return err
		}
	}
	w.pending = make(map[string]*ioc.IOC)
	w.count = 0
	return nil
}

// aggregationKey returns the SHA-256 of (category + "|" + pattern + "|" + domain_hash).
// This is the IOC's Fingerprint. The pipe character is a separator
// that cannot appear in any of the three fields (categories are
// snake_case, patterns are snake_case, domain_hash is lowercase hex).
func aggregationKey(category, domainHash string) string {
	h := sha256.New()
	h.Write([]byte(category))
	h.Write([]byte{'|'})
	h.Write([]byte(patternFromCategory(category)))
	h.Write([]byte{'|'})
	h.Write([]byte(domainHash))
	return hex.EncodeToString(h.Sum(nil))
}

// patternFromCategory returns the canonical pattern name for a category.
// In v0.1 with the regex-only detector, there is one pattern per
// category. In v0.2 with the ML classifier, there may be multiple
// patterns per category, and the event payload would include a
// pattern field; that field is reserved in the §1.1 schema
// (not in the v0.1 wire format, but the Go struct has it as
// `omitempty`).
func patternFromCategory(category string) string {
	return category // 1:1 in v0.1
}

// sourceProviderFromDomainHash looks up the human-readable
// provider name from the domain_hash. The mapping is fixed
// and matches the allowlist in the extension. If the
// domain_hash is not in the map, returns "unknown" (the IOC
// is still valid; it just has a less specific SourceProvider).
func sourceProviderFromDomainHash(domainHash string) string {
	mapping := map[string]string{
		ComputeDomainHash("chatgpt.com"):      "chatgpt",
		ComputeDomainHash("chat.openai.com"):  "chatgpt",
		ComputeDomainHash("claude.ai"):        "claude",
		ComputeDomainHash("gemini.google.com"): "gemini",
		ComputeDomainHash("copilot.microsoft.com"): "copilot",
	}
	if v, ok := mapping[domainHash]; ok {
		return v
	}
	return "unknown"
}

// categoryToIOCType maps a Lens category to an IOCType. The
// mapping is locked; any change requires updating
// plans/AEGISGATE-LENS-ARCHITECTURE-v1.md.
func categoryToIOCType(category string) ioc.IOCType {
	switch category {
	case string(CategoryPIIEmail), string(CategoryPIIPhone),
		string(CategoryPIISSN), string(CategoryPIICreditCard):
		return ioc.IOCTypePIIDetected
	case string(CategorySecretAPIKey):
		return ioc.IOCTypeSecretLeak
	case string(CategorySourceCode):
		return ioc.IOCTypeSecretLeak // source code detection is treated as a secret-leak IOC
	}
	return ioc.IOCTypePIIDetected // default; rejected upstream by Validate()
}

// severityToIOC maps a Lens Severity to an ioc.Severity.
func severityToIOC(s string) ioc.Severity {
	switch Severity(s) {
	case SeverityInfo:
		return ioc.SeverityInfo
	case SeverityLow:
		return ioc.SeverityLow
	case SeverityMedium:
		return ioc.SeverityMedium
	case SeverityHigh:
		return ioc.SeverityHigh
	case SeverityCritical:
		return ioc.SeverityCritical
	}
	return ioc.SeverityInfo
}
