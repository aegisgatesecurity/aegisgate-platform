// SPDX-License-Identifier: Apache-2.0
//go:build !enterprise

// Package audit provides the community-edition SIEMDispatcher type.
//
// SIEM integration (Splunk, Elasticsearch, QRadar, Datadog, etc.) is an
// enterprise-tier feature. In the community edition, NewSIEMDispatcher
// returns a clear error indicating the feature requires an enterprise
// license. The type and method signatures exist so that the rest of
// the codebase compiles without the proprietary SIEM package, and so
// callers can check for the error at runtime.
//
// The enterprise build (pkg/audit/siem_dispatcher.go, build tag: enterprise)
// provides the full implementation with platform-specific forwarding.

package audit

import (
	"context"
	"errors"
	"time"
)

// ErrSIEMEnterpriseOnly is returned when SIEM features are invoked
// in the community edition. Callers should check for this error and
// gracefully degrade (e.g., log a warning and continue with audit
// logging only, no SIEM forwarding).
var ErrSIEMEnterpriseOnly = errors.New("SIEM dispatcher requires enterprise license — see https://aegisgate.dev/pricing for details")

// SIEMDispatcher forwards audit events to external SIEM platforms.
// In the community edition, the type exists for compilation compatibility
// but NewSIEMDispatcher returns ErrSIEMEnterpriseOnly.
type SIEMDispatcher struct{}

// SIEMDispatcherConfig configures the SIEM dispatcher.
// In the community edition, this is unused but must exist for API
// compatibility with the enterprise build.
type SIEMDispatcherConfig struct {
	Manager      interface{}
	EventSource  interface{}
	PollInterval time.Duration
	BatchSize    int
	Source       string
}

// DispatcherStats holds runtime statistics for the SIEM dispatcher.
// In the community edition, all fields are zero-valued.
type DispatcherStats struct {
	EventsPolled    int64
	EventsForwarded int64
	EventsDropped   int64
	Errors          int64
	LastPollTime    time.Time
}

// NewSIEMDispatcher creates a SIEMDispatcher. In the community edition,
// it returns ErrSIEMEnterpriseOnly. Callers should handle this error
// gracefully:
//
//	disp, err := audit.NewSIEMDispatcher(cfg)
//	if err != nil {
//	    if errors.Is(err, audit.ErrSIEMEnterpriseOnly) {
//	        slog.Info("SIEM forwarding disabled (enterprise feature)")
//	    } else {
//	        return fmt.Errorf("SIEM init: %w", err)
//	    }
//	}
func NewSIEMDispatcher(_ SIEMDispatcherConfig) (*SIEMDispatcher, error) {
	return nil, ErrSIEMEnterpriseOnly
}

// Run is a no-op in the community edition. It exists for API
// compatibility — the caller should not reach this method because
// NewSIEMDispatcher returns an error.
func (d *SIEMDispatcher) Run(_ context.Context) {}

// Stop is a no-op in the community edition.
func (d *SIEMDispatcher) Stop() {}

// Stats returns zero-valued stats in the community edition.
func (d *SIEMDispatcher) Stats() DispatcherStats {
	return DispatcherStats{}
}
