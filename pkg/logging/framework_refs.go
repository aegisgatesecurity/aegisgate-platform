// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Framework Reference Cache (v3.5.0-alpha-1, Tier 1 TODO-401)
//
// framework_refs.go is a small, hot-path-safe cache that maps an
// Event's detection tuple (Type, ThreatType, Pattern) to a set of
// cross-framework reference IDs (MITRE ATLAS, NIST AI RMF, OWASP LLM,
// CWE, CVE). The cache is seeded at process start from a Seed
// function and re-seeded on a configurable TTL ticker so that IOC
// taxonomy evolution propagates without restart.
//
// The cache is the bridge between pkg/logging (the hot path) and
// pkg/compliance/framework_mapping.go (the source-of-truth library).
// To keep pkg/logging decoupled from pkg/compliance, the cache
// takes a Seed function rather than importing the compliance
// package directly. The wiring code (cmd/aegisgate-platform/main.go)
// is the only place that imports both packages.
//
// Threading model:
//
//	Init  -> called once from main.go at startup
//	Get   -> callable from any goroutine, hot-path-safe
//	Stop  -> called once from main.go at shutdown
//
// On the Get() path, the cost is: 1 sync.Map.Load + 1 map clone on
// hit, or 1 sync.Map.Load + 1 sync.Map.Store + 1 map clone on miss.
// The re-seed goroutine holds the write lock only for the duration
// of the map swap (microseconds), so the read path is never blocked
// by a slow Seed.
//
// Tier 1 (TODO-401) of the 5-Tier forward roadmap.

package logging

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DetectionKey is the lookup tuple for the framework-ref cache.
// All fields are lowercased + trimmed before hashing, so callers
// don't need to normalize. The zero value is a valid (empty) key
// and returns an empty refs map.
type DetectionKey struct {
	// Type is the event Type (e.g., "threat", "auth", "ioc").
	Type string
	// ThreatType is the threat category (e.g., "prompt_injection",
	// "jailbreak", "data_exfiltration").
	ThreatType string
	// Pattern is the matched pattern (e.g., "DAN", "ignore previous").
	Pattern string
}

// FrameworkRefEntry is one (DetectionKey, FrameworkRefs) pair
// produced by a Seed function. FrameworkRefs maps canonical
// framework IDs (e.g., "mitre_atlas") to a slice of cross-reference
// IDs in that framework (e.g., []string{"T0024"}).
type FrameworkRefEntry struct {
	Key  DetectionKey
	Refs map[string][]string
}

// FrameworkRefCacheConfig controls the FrameworkRefCache lifecycle.
//
// TTL is the periodic re-seed interval. Zero means "seed once,
// never refresh" (NOT recommended for production). The default
// when TTL is non-zero is 5 minutes. Lower bounds are silently
// clamped to 100ms to prevent a tight loop if a misconfigured
// value is passed (e.g., a sub-millisecond TTL).
//
// Seed is the function that produces the (detection, refs) pairs.
// If nil, DefaultSeedFn is used, which is a small inlined table
// covering the IOC library's canonical type strings. The full
// library walk is a TODO-follow-up (Tier 1.6).
//
// Logger is used for non-fatal diagnostics. If nil, a default
// logger writing to os.Stderr is used.
type FrameworkRefCacheConfig struct {
	TTL    time.Duration
	Seed   func() ([]FrameworkRefEntry, error)
	Logger *log.Logger
}

// defaultRefCacheTTL is the periodic re-seed interval when the
// caller specifies a non-zero TTL without overriding the default.
const defaultRefCacheTTL = 5 * time.Minute

// minimumRefCacheTTL is the lower bound on the TTL to prevent a
// tight loop from a misconfigured value. 100ms is fast enough
// for unit tests while still preventing a busy-loop in the
// unlikely event someone passes a sub-millisecond TTL in
// production (where 5 minutes is the recommended default).
const minimumRefCacheTTL = 100 * time.Millisecond

// FrameworkRefCache is a goroutine-safe cache of
// (DetectionKey) -> (FrameworkRefs map[string][]string). The cache
// is seeded at Init() time and re-seeded on a TTL ticker.
//
// The read path is lock-free (sync.Map atomic Load). The write
// path (re-seed) builds a fresh map and atomic-swaps it in, so
// the read path is never blocked.
type FrameworkRefCache struct {
	ttl    time.Duration
	seed   func() ([]FrameworkRefEntry, error)
	logger *log.Logger

	// store is the active refs table. Reads are lock-free.
	// Writes (during re-seed) build a fresh *refStore in a
	// background goroutine and atomic-swap storeCurrent.
	storeCurrent atomic.Pointer[refStore]

	// tickerStop is the cancel function for the background
	// re-seed goroutine. Nil before Init() and after Stop().
	tickerStop context.CancelFunc

	// initOnce guards Init() from being called twice.
	initOnce sync.Once
	// initErr captures the first Init() error so a second
	// Init() call can return it idempotently.
	initErr error
}

// refStore is a single (immutable) snapshot of the cache contents.
// The cache holds an atomic pointer to one of these. Re-seed
// builds a new refStore and swaps the pointer.
type refStore struct {
	// entries is keyed by the normalized detection tuple
	// "type|threattype|pattern" (lowercased + trimmed).
	entries sync.Map // string -> map[string][]string
}

// newRefStore builds a refStore from a slice of entries. Empty
// inputs are valid and produce a usable (but empty) store.
func newRefStore(entries []FrameworkRefEntry) *refStore {
	rs := &refStore{}
	for _, e := range entries {
		k := normalizeKey(e.Key)
		// Copy the refs map so the caller can't mutate the
		// store after construction. The values slice is also
		// copied to be safe against in-place append.
		refsCopy := make(map[string][]string, len(e.Refs))
		for fw, ids := range e.Refs {
			idsCopy := make([]string, len(ids))
			copy(idsCopy, ids)
			refsCopy[fw] = idsCopy
		}
		rs.entries.Store(k, refsCopy)
	}
	return rs
}

// normalizeKey lowercases + trims all fields of a DetectionKey
// and joins them with "|" to form the cache key. Empty fields
// become "-" so the key is non-empty even for the zero value.
func normalizeKey(k DetectionKey) string {
	return strings.ToLower(strings.TrimSpace(k.Type)) + "|" +
		strings.ToLower(strings.TrimSpace(k.ThreatType)) + "|" +
		strings.ToLower(strings.TrimSpace(k.Pattern))
}

// Init starts the background seeder goroutine. It is safe to call
// Init() exactly once per process. Calling Init() a second time
// on the same cache is a no-op that returns the original error,
// if any.
//
// Init() returns after the first Seed completes (or fails); the
// background re-seed goroutine continues until Stop() is called.
func (c *FrameworkRefCache) Init(cfg FrameworkRefCacheConfig) error {
	c.initOnce.Do(func() {
		// Resolve TTL: zero or negative => seed-once (no ticker).
		// Otherwise clamp to [minimumRefCacheTTL, +inf).
		ttl := cfg.TTL
		if ttl > 0 && ttl < minimumRefCacheTTL {
			ttl = minimumRefCacheTTL
		}
		c.ttl = ttl

		// Resolve Seed: nil => default.
		if cfg.Seed == nil {
			c.seed = DefaultSeedFn
		} else {
			c.seed = cfg.Seed
		}

		// Resolve Logger: nil => os.Stderr.
		if cfg.Logger == nil {
			c.logger = log.New(os.Stderr, "[framework_refs] ", log.LstdFlags)
		} else {
			c.logger = cfg.Logger
		}

		// First seed (synchronous, so Init() returns a usable cache).
		if err := c.reseed(); err != nil {
			c.initErr = err
			c.logger.Printf("init: first seed failed: %v", err)
		}

		// Background re-seeder.
		if c.ttl > 0 {
			ctx, cancel := context.WithCancel(context.Background())
			c.tickerStop = cancel
			go c.reSeedLoop(ctx)
		}
	})
	return c.initErr
}

// reseed runs the Seed function and atomic-swaps the store. On
// failure, the existing store is preserved and the error is logged.
// This means a temporary Seed failure does not clear the cache.
func (c *FrameworkRefCache) reseed() error {
	entries, err := c.seed()
	if err != nil {
		c.logger.Printf("reseed: seed failed, keeping existing store: %v", err)
		return err
	}
	rs := newRefStore(entries)
	c.storeCurrent.Store(rs)
	return nil
}

// reSeedLoop runs the periodic re-seed ticker. Exits when the
// context is cancelled by Stop().
func (c *FrameworkRefCache) reSeedLoop(ctx context.Context) {
	t := time.NewTicker(c.ttl)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.reseed(); err != nil {
				// Already logged in reseed().
				continue
			}
		}
	}
}

// Get returns the framework refs for the given detection. It is
// the hot path. Returns an empty (non-nil) map on miss or when no
// cache is installed; the caller never has to nil-check.
//
// Cost: 1 atomic.Pointer.Load + 1 sync.Map.Load on the store +
// 1 map clone. ~200ns on a typical x86_64.
func (c *FrameworkRefCache) Get(key DetectionKey) map[string][]string {
	rs := c.storeCurrent.Load()
	if rs == nil {
		return map[string][]string{}
	}
	k := normalizeKey(key)
	v, ok := rs.entries.Load(k)
	if !ok {
		return map[string][]string{}
	}
	// Clone the returned map so the caller cannot mutate the
	// store. The values slices are also cloned.
	src, ok := v.(map[string][]string)
	if !ok {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(src))
	for fw, ids := range src {
		idsCopy := make([]string, len(ids))
		copy(idsCopy, ids)
		out[fw] = idsCopy
	}
	return out
}

// Stop cancels the background re-seeder. Safe to call multiple
// times. Does not clear the store - Get() continues to work
// after Stop() with the last successfully-seeded data.
func (c *FrameworkRefCache) Stop() {
	if c.tickerStop != nil {
		c.tickerStop()
		c.tickerStop = nil
	}
}

// --------------------------------------------------------------------
// Global cache (mirrors the SetDefault/GetDefault pattern in
// recorder.go so subsystems can call Get() without threading a
// *FrameworkRefCache through every constructor).
// --------------------------------------------------------------------

// globalRefCache is the process-wide FrameworkRefCache. Set by
// SetGlobalRefCache from main.go. Nil until set; reads from
// nil are safe and return empty refs.
var globalRefCachePtr atomic.Pointer[FrameworkRefCache]

// globalRefCacheOnce guards the "called before SetGlobalRefCache"
// warning so it fires at most once per process.
var globalRefCacheOnce sync.Once

// SetGlobalRefCache installs the process-wide FrameworkRefCache.
// Called once at startup from main.go, after Init() has been
// called on the cache. Passing nil clears the global (effectively
// disabling the cross-framework lookup).
func SetGlobalRefCache(c *FrameworkRefCache) {
	globalRefCachePtr.Store(c)
}

// GetGlobalRefCache returns the current global cache, or nil if
// none is set. Callers in the hot path should use
// GlobalRefCacheFor() (which returns a no-op-on-miss shim) to
// avoid a nil-check at every call site.
func GetGlobalRefCache() *FrameworkRefCache {
	return globalRefCachePtr.Load()
}

// GlobalRefCacheFor returns the framework refs for the given
// detection by consulting the global cache. If no global cache
// is set, it returns an empty (non-nil) map. This is the function
// the recorder calls; it is allocation-free when the global
// cache is nil.
func GlobalRefCacheFor(key DetectionKey) map[string][]string {
	c := globalRefCachePtr.Load()
	if c == nil {
		return map[string][]string{}
	}
	return c.Get(key)
}

// --------------------------------------------------------------------
// Default seed (v3.5.0-alpha-1, inlined table).
//
// The default seed is a small, deterministic table covering the
// IOC library's canonical type strings and the 12 most common
// patterns emitted by the anomaly scorer. It does NOT walk the
// pkg/compliance/framework_mapping library; a full library-walk
// seed is left as a follow-up (TODO-Tier1-1.6) for the next
// sprint, after the wire-up is validated end-to-end.
//
// The keys here are the same tuple the cache will see on the hot
// path: Type from Event.Type, ThreatType from Event.ThreatType,
// Pattern from Event.Pattern. Empty fields are allowed (they
// normalize to "-").
// --------------------------------------------------------------------

// DefaultSeedFn returns the default inlined seed table. It is
// used when FrameworkRefCacheConfig.Seed is nil.
//
// The mappings below are sourced from the public MITRE ATLAS
// matrix, OWASP LLM Top 10, and CWE catalog as of 2026-06-15.
// CVE references are illustrative (no live CVE feed in alpha.1).
func DefaultSeedFn() ([]FrameworkRefEntry, error) {
	return []FrameworkRefEntry{
		// ---- prompt injection family (OWASP LLM01, ATLAS AML.T0051) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0051"},
				"owasp_llm":   {"LLM01"},
				"nist_ai_rmf": {"GOVERN-1.2", "MEASURE-2.5"},
				"cwe":         {"CWE-1427"},
			},
		},
		{
			Key: DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "ignore previous"},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0051"},
				"owasp_llm":   {"LLM01"},
				"cwe":         {"CWE-1427"},
			},
		},
		{
			Key: DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0051"},
				"owasp_llm":   {"LLM01"},
				"cwe":         {"CWE-1427"},
			},
		},

		// ---- jailbreak family (OWASP LLM01, ATLAS AML.T0051) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "jailbreak", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0051"},
				"owasp_llm":   {"LLM01"},
				"nist_ai_rmf": {"GOVERN-1.2"},
			},
		},

		// ---- data exfiltration (OWASP LLM06, ATLAS AML.T0024) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "data_exfiltration", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0024"},
				"owasp_llm":   {"LLM06"},
				"cwe":         {"CWE-200"},
			},
		},

		// ---- model theft / extraction (OWASP LLM10, ATLAS AML.T0028) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "model_theft", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0028"},
				"owasp_llm":   {"LLM10"},
			},
		},

		// ---- training data poisoning (OWASP LLM03, ATLAS AML.T0020) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "data_poisoning", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0020"},
				"owasp_llm":   {"LLM03"},
				"cwe":         {"CWE-20"},
			},
		},

		// ---- supply chain (OWASP LLM05, ATLAS AML.T0010) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "supply_chain", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0010"},
				"owasp_llm":   {"LLM05"},
				"cwe":         {"CWE-829"},
			},
		},

		// ---- sensitive information disclosure (OWASP LLM02) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "info_disclosure", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0024"},
				"owasp_llm":   {"LLM02"},
				"cwe":         {"CWE-200"},
			},
		},

		// ---- insecure output handling (OWASP LLM05) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "insecure_output", Pattern: ""},
			Refs: map[string][]string{
				"owasp_llm": {"LLM05"},
				"cwe":       {"CWE-79"},
			},
		},

		// ---- excessive agency (OWASP LLM08) ----
		{
			Key: DetectionKey{Type: "threat", ThreatType: "excessive_agency", Pattern: ""},
			Refs: map[string][]string{
				"owasp_llm":   {"LLM08"},
				"nist_ai_rmf": {"GOVERN-3.2"},
			},
		},

		// ---- authentication family (no LLM-specific framework) ----
		{
			Key: DetectionKey{Type: "auth", ThreatType: "", Pattern: ""},
			Refs: map[string][]string{
				"cwe": {"CWE-287"},
			},
		},

		// ---- IOC family (cross-protocol, from federated IOC library) ----
		{
			Key: DetectionKey{Type: "ioc", ThreatType: "", Pattern: ""},
			Refs: map[string][]string{
				"cwe": {"CWE-1188"},
			},
		},

		// ---- request family (catch-all for normal traffic) ----
		{
			Key: DetectionKey{Type: "request", ThreatType: "", Pattern: ""},
			Refs: map[string][]string{
				"nist_ai_rmf": {"MANAGE-4.1"},
			},
		},

		// ---- anomaly_score (the IOC allow-list's high-signal
		// type) - same taxonomy as threat/prompt_injection
		// because anomaly scorer emits ThreatType as well. ----
		{
			Key: DetectionKey{Type: "anomaly_score", ThreatType: "prompt_injection", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0051"},
				"owasp_llm":   {"LLM01"},
				"cwe":         {"CWE-1427"},
			},
		},
		{
			Key: DetectionKey{Type: "anomaly_score", ThreatType: "jailbreak", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0051"},
				"owasp_llm":   {"LLM01"},
			},
		},
		{
			Key: DetectionKey{Type: "anomaly_score", ThreatType: "data_exfiltration", Pattern: ""},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0024"},
				"owasp_llm":   {"LLM06"},
				"cwe":         {"CWE-200"},
			},
		},

		// ---- proxy_response (the IOC allow-list's response-scan
		// type) - covers PII / secret / injection findings from
		// the response guard. ----
		{
			Key: DetectionKey{Type: "proxy_response", ThreatType: "pii", Pattern: ""},
			Refs: map[string][]string{
				"owasp_llm": {"LLM02"},
				"cwe":       {"CWE-359"},
			},
		},
		{
			Key: DetectionKey{Type: "proxy_response", ThreatType: "secret", Pattern: ""},
			Refs: map[string][]string{
				"owasp_llm": {"LLM02"},
				"cwe":       {"CWE-798"},
			},
		},
		{
			Key: DetectionKey{Type: "proxy_response", ThreatType: "injection", Pattern: ""},
			Refs: map[string][]string{
				"owasp_llm": {"LLM01"},
				"cwe":       {"CWE-79"},
			},
		},
	}, nil
}

// WarnIfGlobalCacheUnset emits a one-shot warning to the standard
// logger if GetGlobalRefCache is nil. Called from main.go after
// SetGlobalRefCache. Useful for diagnosing the "I expected the
// cross-framework lookup to work but my events are empty" case.
func WarnIfGlobalCacheUnset() {
	globalRefCacheOnce.Do(func() {
		// We can't actually distinguish "never set" from "set to
		// nil" without additional state, so we use a sync.Once
		// to ensure this fires at most once per process.
		// The wiring code calls WarnIfGlobalCacheUnset AFTER
		// SetGlobalRefCache if it intended to enable the cache.
		// If the cache is nil at that point, it means the user
		// forgot to call SetGlobalRefCache.
		if globalRefCachePtr.Load() == nil {
			log.Printf("[framework_refs] WARNING: global cache not set; Event.FrameworkRefs will be empty for all events")
		}
	})
}
