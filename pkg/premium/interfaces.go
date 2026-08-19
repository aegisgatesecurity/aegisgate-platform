// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Premium Feature Interfaces
// =========================================================================
//
// Package premium defines Go interfaces for enterprise-tier features.
// These interfaces are the contract between the open-source platform
// core and the proprietary enterprise packages.
//
// Design goals:
//
//  1. The open-source platform (aegisgate-platform) compiles and runs
//     without any enterprise code. It links against these interfaces
//     and uses no-op implementations registered by default.
//
//  2. The enterprise build (aegisgate-enterprise, private repo) provides
//     concrete implementations that register themselves at init() time
//     or are wired explicitly by the enterprise main binary.
//
//  3. Callers in the open-source code depend only on the interfaces,
//     never on concrete enterprise types. This means the open-source
//     binary can be built, tested, and distributed independently.
//
// Registration pattern:
//
//	// Enterprise init():
//	func init() {
//	    premium.RegisterSIEMDispatcherFactory(realFactory{})
//	    premium.RegisterTrustProvider(realTrustProvider{})
//	    premium.RegisterTrustPortalHandler(realPortalHandler{})
//	}
//
//	// Open-source main.go:
//	factory := premium.SIEMDispatcherFactory()
//	disp, err := factory.New(config)
//	// factory is no-op by default; enterprise build overrides.
//
// The interfaces intentionally use minimal method sets — just enough
// for the open-source code to call into premium features. Enterprise
// packages may expose richer APIs directly to enterprise callers.
//
// =========================================================================

package premium

import (
	"context"
	"net/http"
	"time"
)

// ========================================================================
// SIEM Dispatcher
// ========================================================================

// SIEMDispatcherStats holds runtime statistics for the SIEM dispatcher.
// Mirrors audit.DispatcherStats in the community edition.
type SIEMDispatcherStats struct {
	EventsPolled    int64
	EventsForwarded int64
	EventsDropped   int64
	Errors          int64
	LastPollTime    time.Time
}

// SIEMDispatcherConfig configures the SIEM dispatcher. Uses interface{}
// for Manager and EventSource because those types are defined in
// enterprise packages not available to the open-source build.
type SIEMDispatcherConfig struct {
	Manager      interface{} // *siem.Manager (enterprise only)
	EventSource  interface{} // evidence.EventSource
	PollInterval time.Duration
	BatchSize    int
	Source       string
}

// SIEMDispatcher is the interface for the SIEM event dispatcher.
// The community edition returns a no-op implementation.
type SIEMDispatcher interface {
	// Run starts the dispatcher. Blocks until ctx is cancelled or
	// Stop is called.
	Run(ctx context.Context)
	// Stop gracefully shuts down the dispatcher.
	Stop()
	// Stats returns current dispatcher statistics.
	Stats() SIEMDispatcherStats
}

// SIEMDispatcherFactory creates SIEMDispatcher instances.
// The default (community) factory always returns ErrEnterpriseOnly.
type SIEMDispatcherFactory interface {
	// New creates a SIEMDispatcher from the given config.
	New(config SIEMDispatcherConfig) (SIEMDispatcher, error)
}

// ErrEnterpriseOnly is returned by default factory implementations when
// an enterprise feature is invoked in the community edition.
var ErrEnterpriseOnly = errEnterpriseOnly{}

type errEnterpriseOnly struct{}

func (errEnterpriseOnly) Error() string {
	return "feature requires enterprise license — see https://aegisgate.dev/pricing for details"
}

// ========================================================================
// Trust Framework
// ========================================================================

// TrustSession represents a trust monitoring session for an agent.
// The enterprise build provides the full implementation with
// per-session trust scoring, anomaly detection, and attestation.
type TrustSession interface {
	// ID returns the session identifier.
	ID() string
	// AgentID returns the agent identifier for this session.
	AgentID() string
	// Score returns the current trust score (0-100).
	Score() float64
	// End closes the session and returns the final score delta.
	End() (float64, error)
}

// TrustManager manages trust sessions and scoring.
// The community edition returns a no-op implementation.
type TrustManager interface {
	// StartSession begins a new trust session for an agent.
	StartSession(ctx context.Context, agentID string) (TrustSession, error)
	// GetSession returns an active session by ID.
	GetSession(sessionID string) (TrustSession, error)
	// RecordEvent records a behavior event in a session.
	RecordEvent(ctx context.Context, sessionID string, eventType string, metadata map[string]interface{}) error
	// AgentScore returns the lifetime trust score for an agent.
	AgentScore(agentID string) (float64, error)
	// Close shuts down the trust manager.
	Close() error
}

// TrustProvider is the factory for TrustManager instances.
// The default (community) factory always returns ErrEnterpriseOnly.
type TrustProvider interface {
	// NewManager creates a TrustManager from the given config.
	NewManager(config interface{}) (TrustManager, error)
}

// ========================================================================
// Trust Portal HTTP
// ========================================================================

// TrustPortalHandler wires the Trust Portal HTTP endpoints.
// The community edition returns a handler that serves a JSON
// "enterprise_required" response at /trust.
type TrustPortalHandler interface {
	// Wire registers trust portal HTTP routes on the given mux.
	Wire(mux *http.ServeMux)
}

// ========================================================================
// Registration — global factories that enterprise code overrides
// ========================================================================

var (
	siemDispatcherFactory SIEMDispatcherFactory = noopSIEMFactory{}
	trustProvider         TrustProvider         = noopTrustProvider{}
	trustPortalHandler    TrustPortalHandler    = noopTrustPortalHandler{}
)

// RegisterSIEMDispatcherFactory sets the global SIEM dispatcher factory.
// Called by the enterprise build's init() to plug in the real implementation.
func RegisterSIEMDispatcherFactory(f SIEMDispatcherFactory) {
	siemDispatcherFactory = f
}

// SIEMDispatcherFactoryInstance returns the registered SIEM dispatcher factory.
// Returns a no-op factory in the community edition.
func SIEMDispatcherFactoryInstance() SIEMDispatcherFactory {
	return siemDispatcherFactory
}

// RegisterTrustProvider sets the global trust provider.
// Called by the enterprise build's init() to plug in the real implementation.
func RegisterTrustProvider(p TrustProvider) {
	trustProvider = p
}

// TrustProviderInstance returns the registered trust provider.
// Returns a no-op provider in the community edition.
func TrustProviderInstance() TrustProvider {
	return trustProvider
}

// RegisterTrustPortalHandler sets the global trust portal handler.
// Called by the enterprise build's init() to plug in the real implementation.
func RegisterTrustPortalHandler(h TrustPortalHandler) {
	trustPortalHandler = h
}

// TrustPortalHandlerInstance returns the registered trust portal handler.
// Returns a no-op handler in the community edition.
func TrustPortalHandlerInstance() TrustPortalHandler {
	return trustPortalHandler
}

// ========================================================================
// No-op implementations (community edition defaults)
// ========================================================================

type noopSIEMFactory struct{}

func (noopSIEMFactory) New(_ SIEMDispatcherConfig) (SIEMDispatcher, error) {
	return nil, ErrEnterpriseOnly
}

type noopSIEMDispatcher struct{}

func (noopSIEMDispatcher) Run(_ context.Context) {}
func (noopSIEMDispatcher) Stop()                 {}
func (noopSIEMDispatcher) Stats() SIEMDispatcherStats {
	return SIEMDispatcherStats{}
}

type noopTrustProvider struct{}

func (noopTrustProvider) NewManager(_ interface{}) (TrustManager, error) {
	return nil, ErrEnterpriseOnly
}

type noopTrustManager struct{}

func (noopTrustManager) StartSession(_ context.Context, _ string) (TrustSession, error) {
	return nil, ErrEnterpriseOnly
}
func (noopTrustManager) GetSession(_ string) (TrustSession, error) {
	return nil, ErrEnterpriseOnly
}
func (noopTrustManager) RecordEvent(_ context.Context, _ string, _ string, _ map[string]interface{}) error {
	return ErrEnterpriseOnly
}
func (noopTrustManager) AgentScore(_ string) (float64, error) {
	return 0, ErrEnterpriseOnly
}
func (noopTrustManager) Close() error { return nil }

type noopTrustSession struct{}

func (noopTrustSession) ID() string            { return "" }
func (noopTrustSession) AgentID() string       { return "" }
func (noopTrustSession) Score() float64        { return 0 }
func (noopTrustSession) End() (float64, error) { return 0, ErrEnterpriseOnly }

type noopTrustPortalHandler struct{}

func (noopTrustPortalHandler) Wire(mux *http.ServeMux) {
	mux.HandleFunc("/trust", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"enterprise_required","message":"Trust Framework requires enterprise license — see https://aegisgate.dev/pricing for details"}`))
	})
}
