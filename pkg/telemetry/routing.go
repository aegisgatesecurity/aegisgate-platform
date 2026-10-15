// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Telemetry Event Routing
//
// Implements source-specific event routing for the unified telemetry
// receiver. Events from each FOSS product are routed to appropriate
// aggregation logic based on the source field.

package telemetry

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/contracts"
)

// EventRouter routes incoming events to source-specific handlers.
// It maintains per-source statistics and an in-memory IOC fingerprint
// cache for corroboration.
type EventRouter struct {
	mu sync.Mutex

	// Per-source statistics
	sourceStats map[contracts.EventSource]*SourceStats

	// IOC fingerprints observed (for corroboration across sources)
	// Key: ruleID+hashedDomain, Value: list of source+timestamp
	fingerprints map[string][]fingerprintEntry

	// Total events received
	totalEvents int64

	// Total detections across all events
	totalDetections int64

	// Total blocks across all events
	totalBlocks int64

	// Event store reference (for persistence)
	store EventStorer
}

// SourceStats tracks per-source statistics.
type SourceStats struct {
	Events     int64
	Detections int64
	Blocks     int64
	LastEvent  time.Time
	Categories map[string]int
	Severities map[string]int
	Rules      map[string]int
}

// fingerprintEntry records a single observation of a fingerprint.
type fingerprintEntry struct {
	Source    contracts.EventSource
	Timestamp time.Time
}

// EventStorer is the interface for persisting events.
// The server's appendEvent method satisfies this interface.
type EventStorer interface {
	StoreEvent(e contracts.Event) error
}

// NewEventRouter creates a new EventRouter.
func NewEventRouter(store EventStorer) *EventRouter {
	return &EventRouter{
		sourceStats:  make(map[contracts.EventSource]*SourceStats),
		fingerprints: make(map[string][]fingerprintEntry),
		store:        store,
	}
}

// Route processes an event by source, updates statistics, and records
// fingerprints for cross-source corroboration.
func (r *EventRouter) Route(e contracts.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Update per-source stats
	stats, ok := r.sourceStats[e.Source]
	if !ok {
		stats = &SourceStats{
			Categories: make(map[string]int),
			Severities: make(map[string]int),
			Rules:      make(map[string]int),
		}
		r.sourceStats[e.Source] = stats
	}
	stats.Events++
	stats.Detections += int64(e.TotalDetections)
	if e.Blocked {
		stats.Blocks++
	}
	stats.LastEvent = e.Timestamp

	for _, c := range e.Categories {
		stats.Categories[c]++
	}
	for _, s := range e.Severities {
		stats.Severities[s]++
	}
	for _, rule := range e.Rules {
		stats.Rules[rule]++
	}

	// Update global stats
	r.totalEvents++
	r.totalDetections += int64(e.TotalDetections)
	if e.Blocked {
		r.totalBlocks++
	}

	// Record fingerprints for cross-source corroboration
	for _, f := range e.Findings {
		fp := fingerprintKey(f.RuleID, e.HashedDomain)
		r.fingerprints[fp] = append(r.fingerprints[fp], fingerprintEntry{
			Source:    e.Source,
			Timestamp: e.Timestamp,
		})
	}

	// Persist event if store is available
	if r.store != nil {
		if err := r.store.StoreEvent(e); err != nil {
			// Log but don't fail — telemetry should be best-effort
			return fmt.Errorf("persist event: %w", err)
		}
	}

	return nil
}

// GetSourceStats returns statistics for a specific source.
func (r *EventRouter) GetSourceStats(source contracts.EventSource) *SourceStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	stats, ok := r.sourceStats[source]
	if !ok {
		return &SourceStats{
			Categories: make(map[string]int),
			Severities: make(map[string]int),
			Rules:      make(map[string]int),
		}
	}

	// Return a copy
	copied := *stats
	copied.Categories = make(map[string]int, len(stats.Categories))
	for k, v := range stats.Categories {
		copied.Categories[k] = v
	}
	copied.Severities = make(map[string]int, len(stats.Severities))
	for k, v := range stats.Severities {
		copied.Severities[k] = v
	}
	copied.Rules = make(map[string]int, len(stats.Rules))
	for k, v := range stats.Rules {
		copied.Rules[k] = v
	}
	return &copied
}

// GetAllStats returns statistics for all sources.
func (r *EventRouter) GetAllStats() map[contracts.EventSource]*SourceStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make(map[contracts.EventSource]*SourceStats)
	for source := range r.sourceStats {
		s := r.sourceStats[source]
		copied := *s
		copied.Categories = make(map[string]int, len(s.Categories))
		for k, v := range s.Categories {
			copied.Categories[k] = v
		}
		copied.Severities = make(map[string]int, len(s.Severities))
		for k, v := range s.Severities {
			copied.Severities[k] = v
		}
		copied.Rules = make(map[string]int, len(s.Rules))
		for k, v := range s.Rules {
			copied.Rules[k] = v
		}
		result[source] = &copied
	}
	return result
}

// GetTotalEvents returns total events received across all sources.
func (r *EventRouter) GetTotalEvents() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.totalEvents
}

// GetTotalDetections returns total detections across all events.
func (r *EventRouter) GetTotalDetections() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.totalDetections
}

// GetTotalBlocks returns total blocked events.
func (r *EventRouter) GetTotalBlocks() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.totalBlocks
}

// GetCorroboration returns how many distinct sources have observed
// a given fingerprint (ruleID + hashedDomain). This enables the
// "1 customer's threat = all customers protected" network effect.
func (r *EventRouter) GetCorroboration(ruleID, hashedDomain string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	fp := fingerprintKey(ruleID, hashedDomain)
	entries := r.fingerprints[fp]

	// Count distinct sources
	sources := make(map[contracts.EventSource]bool)
	for _, e := range entries {
		sources[e.Source] = true
	}
	return len(sources)
}

// PruneFingerprints removes fingerprint entries older than the given duration.
func (r *EventRouter) PruneFingerprints(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for fp, entries := range r.fingerprints {
		var kept []fingerprintEntry
		for _, e := range entries {
			if e.Timestamp.After(cutoff) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(r.fingerprints, fp)
		} else {
			r.fingerprints[fp] = kept
		}
	}
}

// fingerprintKey creates a cache key from ruleID and hashedDomain.
func fingerprintKey(ruleID, hashedDomain string) string {
	return ruleID + ":" + hashedDomain
}

// SourceStatsSummary is a JSON-serializable summary of all source stats.
type SourceStatsSummary struct {
	TotalEvents     int64                          `json:"total_events"`
	TotalDetections int64                          `json:"total_detections"`
	TotalBlocks     int64                          `json:"total_blocks"`
	BySource        map[string]*SourceStatsSummary `json:"by_source"`
}

// SourceStatsSummary is per-source summary.
type SourceStatsSummaryEntry struct {
	Events     int            `json:"events"`
	Detections int            `json:"detections"`
	Blocks     int            `json:"blocks"`
	LastEvent  string         `json:"last_event"`
	Categories map[string]int `json:"categories"`
	Severities map[string]int `json:"severities"`
	TopRules   []ruleCount    `json:"top_rules,omitempty"`
}

// ruleCount is a rule ID with its observation count.
type ruleCount struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// GetSummary returns a JSON-serializable summary of all telemetry stats.
func (r *EventRouter) GetSummary() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()

	bySource := make(map[string]interface{})
	for source, stats := range r.sourceStats {
		// Get top 10 rules by count
		var topRules []ruleCount
		for rule, count := range stats.Rules {
			topRules = append(topRules, ruleCount{Rule: rule, Count: count})
		}
		// Sort by count descending (simple bubble sort for small lists)
		for i := 0; i < len(topRules); i++ {
			for j := i + 1; j < len(topRules); j++ {
				if topRules[j].Count > topRules[i].Count {
					topRules[i], topRules[j] = topRules[j], topRules[i]
				}
			}
		}
		if len(topRules) > 10 {
			topRules = topRules[:10]
		}

		bySource[string(source)] = map[string]interface{}{
			"events":     stats.Events,
			"detections": stats.Detections,
			"blocks":     stats.Blocks,
			"last_event": stats.LastEvent.Format(time.RFC3339),
			"categories": stats.Categories,
			"severities": stats.Severities,
			"top_rules":  topRules,
		}
	}

	return map[string]interface{}{
		"total_events":     r.totalEvents,
		"total_detections": r.totalDetections,
		"total_blocks":     r.totalBlocks,
		"by_source":        bySource,
	}
}

// SanitizeSource validates a source string and returns the canonical
// contracts.EventSource value.
func SanitizeSource(source string) (contracts.EventSource, error) {
	switch strings.ToLower(source) {
	case "lens":
		return contracts.SourceLens, nil
	case "rampart":
		return contracts.SourceRampart, nil
	case "scanner":
		return contracts.SourceScanner, nil
	case "mcp":
		return contracts.SourceMCP, nil
	case "platform":
		return contracts.SourcePlatform, nil
	default:
		return "", fmt.Errorf("unknown source: %s", source)
	}
}
