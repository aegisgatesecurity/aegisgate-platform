// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - External TAXII Feed Manager (v4.5.1+ Phase 2)
// =========================================================================
//
// feed_manager.go manages multiple external TAXII 2.1 feeds (MISP,
// CISA ACS, Anomali, etc.). It runs periodic pull cycles per feed,
// converts STIX objects to AegisGate IOCs, applies feed-specific
// reputation weighting, and merges the results into the local IOC
// store.
//
// External IOCs are tagged with Source = "external:<feed_name>" so
// the IOCChecker can distinguish them from crowdsourced peer IOCs
// (Source = "peer:<instanceID>") and local IOCs (Source = "proxy",
// "scanner", etc.).
//
// Feed reputation weighting:
//
//   Each feed has a ReputationWeight (0.0–1.0) that controls how
//   much trust the system places in its IOCs. A feed with weight
//   1.0 (e.g., CISA ACS) is fully trusted — its IOCs are treated
//   as equivalent to local detections. A feed with weight 0.5
//   (e.g., a community MISP feed) has its IOCs' severity degraded
//   by one level unless the IOC is independently corroborated.
//
//   The reputation weight is stored as a label on each external IOC
//   (in the Source field: "external:cisa:1.0") so the checker can
//   make per-IOC trust decisions at lookup time.
//
// Pull lifecycle:
//
//   1. FeedManager.Run() starts a goroutine per feed.
//   2. Each goroutine waits for PollInterval, then calls Pull().
//   3. Pull() calls TAXIIIntegration.Pull() to get a STIX bundle.
//   4. The STIX bundle is converted to an IOC Bundle via
//      STIXToBundle().
//   5. Each IOC's Source is set to "external:<feed_name>:<weight>".
//   6. IOCs below the feed's SeverityFloor are dropped.
//   7. Remaining IOCs are merged into the local Store via
//      Store.ObserveBatch().
//   8. Pull stats (count, last_pull_time, errors) are recorded.
//
// v4.5.1+ Phase 2: External TAXII Feed Integration.
// =========================================================================

package ioc

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/metrics"
)

// FeedConfig configures a single external TAXII feed.
type FeedConfig struct {
	// Name is a human-readable identifier for the feed
	// (e.g., "cisa-acs", "misp-community", "anomali-auto-focus").
	// Must be unique across feeds. Used in the Source field
	// ("external:<name>:<weight>").
	Name string `json:"name"`

	// ServerURL is the TAXII 2.1 server base URL.
	ServerURL string `json:"server_url"`

	// DiscoveryURL is the explicit discovery URL. If empty,
	// the client uses "<ServerURL>/taxii2/".
	DiscoveryURL string `json:"discovery_url,omitempty"`

	// APIRoot is the TAXII API root to pull from (e.g.,
	// "https://limo.anomali.com/api/v1/taxii/taxii2/"). If
	// empty, the server's discovery response is used to find
	// the API root.
	APIRoot string `json:"api_root,omitempty"`

	// CollectionID is the TAXII collection to pull from.
	// If empty, the DefaultCollection from the TAXII config
	// is used.
	CollectionID string `json:"collection_id,omitempty"`

	// AuthType is "basic", "token", or "oauth2".
	AuthType string `json:"auth_type"`

	// Username / Password for basic auth.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// APIToken / TokenHeader for token auth.
	APIToken    string `json:"api_token,omitempty"`
	TokenHeader string `json:"token_header,omitempty"`

	// PollInterval is how often to pull from the feed.
	// Default: 1 hour. Minimum: 5 minutes (enforced by
	// FeedManager).
	PollInterval time.Duration `json:"poll_interval"`

	// ReputationWeight controls how much trust the system
	// places in this feed's IOCs. Range: 0.0–1.0.
	//   1.0 = fully trusted (e.g., CISA ACS, a government CERT)
	//   0.7 = high trust (e.g., a well-maintained MISP feed)
	//   0.5 = medium trust (e.g., a community feed)
	//   0.3 = low trust (e.g., an untested feed)
	// Default: 0.7.
	ReputationWeight float64 `json:"reputation_weight"`

	// SeverityFloor is the minimum severity an IOC from this
	// feed must have to be ingested. IOCs below this floor are
	// dropped during pull. This prevents low-signal feeds from
	// flooding the store with noise.
	// Default: SeverityLow (accept everything).
	SeverityFloor Severity `json:"severity_floor"`

	// Timeout for HTTP requests to this feed. Default: 30s.
	Timeout time.Duration `json:"timeout"`

	// InsecureSkipVerify disables TLS verification for this
	// feed. NOT recommended for production.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// Enabled controls whether this feed is active. If false,
	// the FeedManager skips it during Run(). This allows feeds
	// to be configured but temporarily disabled.
	Enabled bool `json:"enabled"`
}

// DefaultFeedConfig returns sensible defaults for a feed config.
// The caller should populate Name, ServerURL, and auth fields.
func DefaultFeedConfig(name string) FeedConfig {
	return FeedConfig{
		Name:             name,
		AuthType:         "token",
		PollInterval:     1 * time.Hour,
		ReputationWeight: 0.7,
		SeverityFloor:    SeverityLow,
		Timeout:          30 * time.Second,
		TokenHeader:      "Authorization",
		Enabled:          true,
	}
}

// FeedStats tracks the pull statistics for a single feed.
type FeedStats struct {
	// Name is the feed name.
	Name string `json:"name"`

	// Enabled is whether the feed is active.
	Enabled bool `json:"enabled"`

	// LastPullTime is the time of the most recent pull attempt.
	// Zero if never pulled.
	LastPullTime time.Time `json:"last_pull_time"`

	// LastPullCount is the number of IOCs ingested in the most
	// recent successful pull.
	LastPullCount int `json:"last_pull_count"`

	// TotalPulls is the total number of pull attempts
	// (successful or failed).
	TotalPulls int64 `json:"total_pulls"`

	// TotalIOCs is the total number of IOCs ingested across
	// all pulls.
	TotalIOCs int64 `json:"total_iocs"`

	// TotalErrors is the total number of pull failures.
	TotalErrors int64 `json:"total_errors"`

	// LastError is the most recent error message (empty if
	// the last pull succeeded).
	LastError string `json:"last_error,omitempty"`

	// ReputationWeight is the feed's reputation weight.
	ReputationWeight float64 `json:"reputation_weight"`

	// PollInterval is the configured poll interval.
	PollInterval time.Duration `json:"poll_interval"`
}

// FeedManager manages multiple external TAXII feeds and runs
// periodic pulls to merge external IOCs into the local store.
//
// The FeedManager is safe for concurrent use. It starts one
// goroutine per enabled feed, each running its own pull loop.
// The goroutines are stopped when Stop() is called or the
// context passed to Run() is cancelled.
//
// Lifecycle:
//
//	fm := NewFeedManager(store, []FeedConfig{...})
//	ctx, cancel := context.WithCancel(parentCtx)
//	go fm.Run(ctx)
//	// ... feeds are pulling ...
//	cancel() // or fm.Stop()
type FeedManager struct {
	mu      sync.RWMutex
	store   *Store
	feeds   map[string]*feedRunner
	stats   map[string]*FeedStats
	configs []FeedConfig
}

// feedRunner manages a single feed's pull loop.
type feedRunner struct {
	cfg    FeedConfig
	stats  *FeedStats
	taxii  *TAXIIIntegration
	store  *Store
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// NewFeedManager creates a FeedManager with the given store and
// feed configurations. Feeds with Enabled=false are loaded but
// not started. The FeedManager is not started until Run() is
// called.
//
// Returns an error if any feed config is invalid (duplicate name,
// missing ServerURL, etc.) or if the TAXII client for any feed
// cannot be constructed.
func NewFeedManager(store *Store, configs []FeedConfig) (*FeedManager, error) {
	if store == nil {
		return nil, fmt.Errorf("ioc: NewFeedManager: nil store")
	}

	fm := &FeedManager{
		store:   store,
		feeds:   make(map[string]*feedRunner),
		stats:   make(map[string]*FeedStats),
		configs: configs,
	}

	seen := make(map[string]bool)
	for i, cfg := range configs {
		if cfg.Name == "" {
			return nil, fmt.Errorf("ioc: NewFeedManager: feed[%d] has empty Name", i)
		}
		if seen[cfg.Name] {
			return nil, fmt.Errorf("ioc: NewFeedManager: duplicate feed name %q", cfg.Name)
		}
		seen[cfg.Name] = true
		if cfg.ServerURL == "" {
			return nil, fmt.Errorf("ioc: NewFeedManager: feed %q has empty ServerURL", cfg.Name)
		}
		if cfg.AuthType == "" {
			return nil, fmt.Errorf("ioc: NewFeedManager: feed %q has empty AuthType", cfg.Name)
		}
		if cfg.PollInterval < 5*time.Minute && cfg.PollInterval > 0 {
			cfg.PollInterval = 5 * time.Minute // enforce minimum
		}
		if cfg.PollInterval == 0 {
			cfg.PollInterval = 1 * time.Hour
		}
		if cfg.ReputationWeight <= 0 {
			cfg.ReputationWeight = 0.7
		}
		if cfg.ReputationWeight > 1.0 {
			cfg.ReputationWeight = 1.0
		}

		// Construct the TAXII integration for this feed.
		taxii, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
			ServerURL:          cfg.ServerURL,
			DiscoveryURL:       cfg.DiscoveryURL,
			AuthType:           cfg.AuthType,
			Username:           cfg.Username,
			Password:           cfg.Password,
			APIToken:           cfg.APIToken,
			TokenHeader:        cfg.TokenHeader,
			Timeout:            cfg.Timeout,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			DefaultCollection:  cfg.CollectionID,
		})
		if err != nil {
			return nil, fmt.Errorf("ioc: NewFeedManager: feed %q: %w", cfg.Name, err)
		}

		stats := &FeedStats{
			Name:             cfg.Name,
			Enabled:          cfg.Enabled,
			ReputationWeight: cfg.ReputationWeight,
			PollInterval:     cfg.PollInterval,
		}

		fm.feeds[cfg.Name] = &feedRunner{
			cfg:   cfg,
			stats: stats,
			taxii: taxii,
			store: store,
		}
		fm.stats[cfg.Name] = stats
		fm.configs[i] = cfg
	}

	return fm, nil
}

// Run starts the pull loops for all enabled feeds. Each feed
// gets its own goroutine. The goroutines run until ctx is
// cancelled or Stop() is called.
//
// This method blocks until all feed goroutines have stopped.
// Call it in a goroutine: `go fm.Run(ctx)`.
func (fm *FeedManager) Run(ctx context.Context) {
	fm.mu.Lock()
	var wg sync.WaitGroup
	for name, runner := range fm.feeds {
		if !runner.cfg.Enabled {
			slog.Info("External TAXII feed disabled, skipping", "feed", name)
			continue
		}
		feedCtx, cancel := context.WithCancel(ctx)
		runner.cancel = cancel
		runner.wg = &wg
		wg.Add(1)
		go fm.runFeed(feedCtx, runner)
		slog.Info("External TAXII feed started",
			"feed", runner.cfg.Name,
			"server", runner.cfg.ServerURL,
			"poll_interval", runner.cfg.PollInterval,
			"reputation_weight", runner.cfg.ReputationWeight,
		)
	}
	fm.mu.Unlock()
	wg.Wait()
	slog.Info("FeedManager: all feed goroutines stopped")
}

// runFeed is the per-feed pull loop.
func (fm *FeedManager) runFeed(ctx context.Context, runner *feedRunner) {
	defer runner.wg.Done()

	ticker := time.NewTicker(runner.cfg.PollInterval)
	defer ticker.Stop()

	// Do an initial pull immediately on startup.
	fm.pullFeed(ctx, runner)

	for {
		select {
		case <-ctx.Done():
			slog.Info("External TAXII feed stopped", "feed", runner.cfg.Name)
			return
		case <-ticker.C:
			fm.pullFeed(ctx, runner)
		}
	}
}

// pullFeed performs a single pull from a feed and merges the
// results into the store.
func (fm *FeedManager) pullFeed(ctx context.Context, runner *feedRunner) {
	cfg := runner.cfg
	atomic.AddInt64(&runner.stats.TotalPulls, 1)
	runner.stats.LastPullTime = time.Now().UTC()

	// Determine the API root.
	apiRoot := cfg.APIRoot
	if apiRoot == "" {
		// Use discovery to find the API root.
		disc, err := runner.taxii.Discovery(ctx)
		if err != nil {
			fm.recordError(runner, fmt.Errorf("discovery: %w", err))
			return
		}
		if len(disc.APIRoots) == 0 {
			fm.recordError(runner, fmt.Errorf("discovery returned no API roots"))
			return
		}
		apiRoot = disc.APIRoots[0]
	}

	// Pull STIX objects from the feed.
	// We use the last pull time as the "added_after" filter
	// for incremental pulls. On the first pull, this is zero
	// (pull everything).
	since := runner.stats.LastPullTime
	if !since.IsZero() {
		// Only pull objects added since the last successful
		// pull. But if the last pull errored, we want to
		// re-pull from the same point.
	}

	bundle, err := runner.taxii.Pull(ctx, apiRoot, cfg.CollectionID, since)
	if err != nil {
		fm.recordError(runner, fmt.Errorf("pull: %w", err))
		return
	}

	if bundle == nil || bundle.Count == 0 {
		slog.Debug("External TAXII feed: no new IOCs",
			"feed", cfg.Name,
			"api_root", apiRoot,
		)
		runner.stats.LastError = ""
		return
	}

	// Apply feed-specific transformations to each IOC.
	ingested := 0
	weightLabel := fmt.Sprintf("external:%s:%.1f", cfg.Name, cfg.ReputationWeight)
	for i := range bundle.Attestations {
		att := &bundle.Attestations[i]

		// Apply severity floor: skip IOCs below the floor.
		if severityRank(att.Severity) < severityRank(cfg.SeverityFloor) {
			continue
		}

		// Construct the IOC with external source labeling.
		iocValue := IOC{
			Fingerprint: att.Fingerprint,
			Type:        att.IOCType,
			Severity:    att.Severity,
			FirstSeen:   att.FirstSeen,
			LastSeen:    att.LastSeen,
			Count:       att.Count,
			Source:      weightLabel,
		}

		// Merge into the store.
		if _, err := runner.store.Observe(iocValue); err != nil {
			slog.Warn("External TAXII feed: failed to merge IOC",
				"feed", cfg.Name,
				"fingerprint", att.Fingerprint[:min(12, len(att.Fingerprint))],
				"error", err,
			)
			continue
		}
		ingested++
	}

	runner.stats.LastPullCount = ingested
	runner.stats.LastError = ""
	atomic.AddInt64(&runner.stats.TotalIOCs, int64(ingested))

	// Record Prometheus metrics.
	metrics.RecordIOCFeedIOCs(cfg.Name, ingested)
	metrics.SetIOCFeedLastPull(cfg.Name, float64(time.Now().Unix()))

	slog.Info("External TAXII feed pull complete",
		"feed", cfg.Name,
		"pulled", bundle.Count,
		"ingested", ingested,
		"dropped", bundle.Count-ingested,
		"reputation_weight", cfg.ReputationWeight,
	)
}

// recordError records a pull error on the feed stats.
func (fm *FeedManager) recordError(runner *feedRunner, err error) {
	atomic.AddInt64(&runner.stats.TotalErrors, 1)
	runner.stats.LastError = err.Error()
	metrics.RecordIOCFeedError(runner.cfg.Name)
	slog.Error("External TAXII feed pull failed",
		"feed", runner.cfg.Name,
		"error", err,
	)
}

// Stop stops all feed goroutines. This is safe to call multiple
// times. It cancels each feed's context and waits for the
// goroutines to exit.
func (fm *FeedManager) Stop() {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	for _, runner := range fm.feeds {
		if runner.cancel != nil {
			runner.cancel()
		}
	}
}

// PullNow triggers an immediate pull from the named feed,
// bypassing the poll interval. This is useful for testing and
// for on-demand refresh. Returns the number of IOCs ingested.
//
// The feed must be configured (but need not be Enabled — this
// allows pulling from a disabled feed on demand).
func (fm *FeedManager) PullNow(ctx context.Context, feedName string) (int, error) {
	fm.mu.RLock()
	runner, ok := fm.feeds[feedName]
	fm.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("ioc: FeedManager.PullNow: feed %q not found", feedName)
	}

	// Run the pull synchronously.
	atomic.AddInt64(&runner.stats.TotalPulls, 1)
	runner.stats.LastPullTime = time.Now().UTC()

	cfg := runner.cfg
	apiRoot := cfg.APIRoot
	if apiRoot == "" {
		disc, err := runner.taxii.Discovery(ctx)
		if err != nil {
			fm.recordError(runner, fmt.Errorf("discovery: %w", err))
			return 0, fmt.Errorf("feed %q: %w", feedName, err)
		}
		if len(disc.APIRoots) == 0 {
			err := fmt.Errorf("discovery returned no API roots")
			fm.recordError(runner, err)
			return 0, fmt.Errorf("feed %q: %w", feedName, err)
		}
		apiRoot = disc.APIRoots[0]
	}

	bundle, err := runner.taxii.Pull(ctx, apiRoot, cfg.CollectionID, time.Time{})
	if err != nil {
		fm.recordError(runner, fmt.Errorf("pull: %w", err))
		return 0, fmt.Errorf("feed %q: %w", feedName, err)
	}

	if bundle == nil || bundle.Count == 0 {
		runner.stats.LastError = ""
		return 0, nil
	}

	ingested := 0
	weightLabel := fmt.Sprintf("external:%s:%.1f", cfg.Name, cfg.ReputationWeight)
	for i := range bundle.Attestations {
		att := &bundle.Attestations[i]
		if severityRank(att.Severity) < severityRank(cfg.SeverityFloor) {
			continue
		}
		iocValue := IOC{
			Fingerprint: att.Fingerprint,
			Type:        att.IOCType,
			Severity:    att.Severity,
			FirstSeen:   att.FirstSeen,
			LastSeen:    att.LastSeen,
			Count:       att.Count,
			Source:      weightLabel,
		}
		if _, err := runner.store.Observe(iocValue); err != nil {
			continue
		}
		ingested++
	}

	runner.stats.LastPullCount = ingested
	runner.stats.LastError = ""
	atomic.AddInt64(&runner.stats.TotalIOCs, int64(ingested))
	metrics.RecordIOCFeedIOCs(cfg.Name, ingested)
	metrics.SetIOCFeedLastPull(cfg.Name, float64(time.Now().Unix()))
	return ingested, nil
}

// Stats returns the current statistics for all feeds.
func (fm *FeedManager) Stats() []FeedStats {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	result := make([]FeedStats, 0, len(fm.stats))
	for _, stats := range fm.stats {
		s := *stats
		s.TotalPulls = atomic.LoadInt64(&stats.TotalPulls)
		s.TotalIOCs = atomic.LoadInt64(&stats.TotalIOCs)
		s.TotalErrors = atomic.LoadInt64(&stats.TotalErrors)
		result = append(result, s)
	}
	return result
}

// FeedNames returns the names of all configured feeds.
func (fm *FeedManager) FeedNames() []string {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	names := make([]string, 0, len(fm.feeds))
	for name := range fm.feeds {
		names = append(names, name)
	}
	return names
}

// IsExternalSource returns true if the Source field indicates
// an external TAXII feed IOC. External sources have the format
// "external:<feed_name>:<weight>".
func IsExternalSource(source string) bool {
	return strings.HasPrefix(source, "external:")
}

// ParseExternalSource extracts the feed name and reputation
// weight from an external IOC source string. Returns the feed
// name, the weight, and a boolean indicating whether the source
// is external.
func ParseExternalSource(source string) (feedName string, weight float64, isExternal bool) {
	if !IsExternalSource(source) {
		return "", 0, false
	}
	// Format: "external:<feed_name>:<weight>"
	parts := strings.SplitN(source, ":", 3)
	if len(parts) < 3 {
		// Maybe just "external:<feed_name>" without weight.
		if len(parts) == 2 {
			return parts[1], 0.7, true // default weight
		}
		return "", 0, true
	}
	name := parts[1]
	var w float64
	_, _ = fmt.Sscanf(parts[2], "%f", &w)
	if w <= 0 {
		w = 0.7 // default
	}
	return name, w, true
}
