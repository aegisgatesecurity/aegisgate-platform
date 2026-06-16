// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - TAXII Integration for IOC Bundles (v3.5.0+, Tier 2 TODO-403)
//
// taxii_integration.go wraps the upstream threatintel.TAXIIClient
// and adapts its API to the IOC library's Bundle type. The
// wrapper provides four entry points:
//
//   - Push(bundle, apiRoot, collectionID) -> envelopes
//   - Pull(ctx, apiRoot, collectionID, since) -> *ioc.Bundle
//   - Discovery(ctx) -> ti.TAXIIDiscovery
//   - GetCollections(ctx, apiRoot) -> ti.TAXIICollections
//
// All four call the upstream TAXIIClient. The Push and Pull
// paths also do the IOC <-> STIX conversion (via BundleToSTIX
// and STIXToBundle) so the caller works in AegisGate-domain
// types.
//
// Tier 2 (TODO-403) of the 5-Tier forward roadmap.

package ioc

import (
	"context"
	"fmt"
	"time"

	ti "github.com/aegisgatesecurity/aegisgate/pkg/threatintel"
)

// TAXIIIntegrationConfig configures a TAXII integration. The
// zero value is invalid (ServerURL and AuthType are required);
// use NewTAXIIIntegration to construct one.
type TAXIIIntegrationConfig struct {
	// ServerURL is the TAXII 2.1 server base URL
	// (e.g., "https://taxii.example.com/api2"). Required.
	ServerURL string
	// DiscoveryURL is the explicit discovery URL. If empty,
	// the client uses "<ServerURL>/taxii2/".
	DiscoveryURL string
	// AuthType is "basic", "token", or "oauth2". Required.
	AuthType string
	// Username / Password for basic auth.
	Username string
	Password string
	// APIToken / TokenHeader for token auth.
	APIToken    string
	TokenHeader string
	// Timeout for HTTP requests. Default 30s.
	Timeout time.Duration
	// InsecureSkipVerify disables TLS verification. NOT
	// recommended for production.
	InsecureSkipVerify bool
	// DefaultCollection is the collection ID used by Push
	// when the caller does not specify one. Optional.
	DefaultCollection string
}

// TAXIIIntegration wraps a threatintel.TAXIIClient and
// translates between the IOC library's Bundle type and the
// STIX 2.1 Bundle that the TAXII client expects.
//
// The wrapper is safe for concurrent use. The underlying
// threatintel.TAXIIClient is also safe.
//
// Typical lifecycle:
//
//	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{...})
//	if err != nil { ... }
//	defer ti.Close()
//
//	// Push
//	envelopes, err := ti.Push(ctx, bundle, "https://taxii.example.com/api1", "collection-42")
//
//	// Pull
//	pulled, err := ti.Pull(ctx, "https://taxii.example.com/api1", "collection-42", time.Time{})
type TAXIIIntegration struct {
	cfg TAXIIIntegrationConfig
	cli *ti.TAXIIClient
}

// NewTAXIIIntegration constructs a TAXIIIntegration. Returns
// an error if the config is invalid (e.g., missing ServerURL
// or AuthType) or if the underlying client fails to construct.
func NewTAXIIIntegration(cfg TAXIIIntegrationConfig) (*TAXIIIntegration, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("ioc: NewTAXIIIntegration: ServerURL is required")
	}
	if cfg.AuthType == "" {
		return nil, fmt.Errorf("ioc: NewTAXIIIntegration: AuthType is required (basic, token, or oauth2)")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	tiCfg := ti.DefaultTAXIIConfig()
	tiCfg.ServerURL = cfg.ServerURL
	tiCfg.DiscoveryURL = cfg.DiscoveryURL
	tiCfg.AuthType = cfg.AuthType
	tiCfg.Username = cfg.Username
	tiCfg.Password = cfg.Password
	tiCfg.APIToken = cfg.APIToken
	tiCfg.TokenHeader = cfg.TokenHeader
	tiCfg.Timeout = timeout
	tiCfg.TLS.InsecureSkipVerify = cfg.InsecureSkipVerify
	tiCfg.DefaultCollection = cfg.DefaultCollection
	cli, err := ti.NewTAXIIClient(tiCfg)
	if err != nil {
		return nil, fmt.Errorf("ioc: NewTAXIIIntegration: %w", err)
	}
	return &TAXIIIntegration{cfg: cfg, cli: cli}, nil
}

// Push uploads an AegisGate IOC Bundle to a TAXII collection.
// The bundle is converted to STIX (via BundleToSTIX) and
// pushed in a single TAXII request. Returns the envelope
// (TAXII server's acknowledgement) on success.
func (t *TAXIIIntegration) Push(ctx context.Context, b *Bundle, apiRoot, collectionID string) (*ti.TAXIIEnvelopes, error) {
	if b == nil {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.Push: nil bundle")
	}
	if apiRoot == "" {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.Push: empty apiRoot")
	}
	if collectionID == "" {
		collectionID = t.cfg.DefaultCollection
		if collectionID == "" {
			return nil, fmt.Errorf("ioc: TAXIIIntegration.Push: empty collectionID (and no DefaultCollection configured)")
		}
	}
	stixBundle, err := BundleToSTIX(b)
	if err != nil {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.Push: convert: %w", err)
	}
	envelopes, err := t.cli.AddObjects(ctx, apiRoot, collectionID, stixBundle)
	if err != nil {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.Push: add objects: %w", err)
	}
	return envelopes, nil
}

// Pull downloads STIX objects from a TAXII collection and
// converts them to an AegisGate IOC Bundle. The since
// parameter is a time filter: only objects added after this
// time are returned. Pass time.Time{} (zero) for "all
// objects".
//
// The conversion is lossy: STIX objects that are not
// Indicators are skipped, and Indicators that cannot be
// parsed are skipped (see STIXIndicatorToIOC for details).
// The returned Bundle's Count is the number of IOCs that
// were successfully converted.
func (t *TAXIIIntegration) Pull(ctx context.Context, apiRoot, collectionID string, since time.Time) (*Bundle, error) {
	if apiRoot == "" {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.Pull: empty apiRoot")
	}
	if collectionID == "" {
		collectionID = t.cfg.DefaultCollection
		if collectionID == "" {
			return nil, fmt.Errorf("ioc: TAXIIIntegration.Pull: empty collectionID (and no DefaultCollection configured)")
		}
	}
	opts := &ti.TAXIIGetObjectsRequest{}
	if !since.IsZero() {
		opts.AddedAfter = since
	}
	stixBundle, _, err := t.cli.GetObjects(ctx, apiRoot, collectionID, opts)
	if err != nil {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.Pull: get objects: %w", err)
	}
	if stixBundle == nil {
		// Empty collection. Return an empty bundle rather
		// than nil, so the caller doesn't need to nil-check.
		out := NewBundle(t.cfg.ServerURL)
		return out, nil
	}
	out, err := STIXToBundle(stixBundle, "")
	if err != nil {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.Pull: convert: %w", err)
	}
	return out, nil
}

// Discovery calls the TAXII server's discovery endpoint and
// returns the list of available API roots. The caller can
// then call GetCollections on each API root to discover
// collections.
func (t *TAXIIIntegration) Discovery(ctx context.Context) (*ti.TAXIIDiscovery, error) {
	disc, err := t.cli.Discovery(ctx)
	if err != nil {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.Discovery: %w", err)
	}
	return disc, nil
}

// GetCollections lists the collections available at the given
// API root.
func (t *TAXIIIntegration) GetCollections(ctx context.Context, apiRoot string) (*ti.TAXIICollections, error) {
	if apiRoot == "" {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.GetCollections: empty apiRoot")
	}
	cols, err := t.cli.GetCollections(ctx, apiRoot)
	if err != nil {
		return nil, fmt.Errorf("ioc: TAXIIIntegration.GetCollections: %w", err)
	}
	return cols, nil
}

// Close releases the underlying HTTP client. As of v3.5.0+,
// the threatintel TAXIIClient does not hold persistent
// connections, so Close is a no-op; the method is present
// for API symmetry with future versions.
func (t *TAXIIIntegration) Close() error {
	return nil
}
