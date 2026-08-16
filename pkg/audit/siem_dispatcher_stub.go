// SPDX-License-Identifier: Apache-2.0
//go:build !enterprise

// Package audit provides a community-edition stub for the SIEMDispatcher
// type. The real SIEMDispatcher implementation lives in the enterprise
// build (pkg/audit/siem_dispatcher.go, build tag: enterprise).
//
// In the community edition, SIEM forwarding is not available. The stub
// allows the codebase to compile without the proprietary SIEM package.

package audit

import (
	"context"
	"time"
)

// SIEMDispatcher is a no-op stub for the community edition.
// In the enterprise edition, this type forwards audit events to
// external SIEM platforms (Splunk, Elasticsearch, QRadar, etc.).
type SIEMDispatcher struct{}

// SIEMDispatcherConfig is the configuration for the SIEM dispatcher.
// In the community edition, this is unused but must exist for API
// compatibility.
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

// NewSIEMDispatcher creates a no-op SIEMDispatcher in the community edition.
// It always returns nil and an error indicating SIEM is enterprise-only.
func NewSIEMDispatcher(_ SIEMDispatcherConfig) (*SIEMDispatcher, error) {
	return nil, errSIEMEnterpriseOnly
}

// Run is a no-op in the community edition.
func (d *SIEMDispatcher) Run(_ context.Context) {}

// Stop is a no-op in the community edition.
func (d *SIEMDispatcher) Stop() {}

// Stats returns empty stats in the community edition.
func (d *SIEMDispatcher) Stats() DispatcherStats {
	return DispatcherStats{}
}

// errSIEMEnterpriseOnly is returned when SIEM features are used
// in the community edition.
var errSIEMEnterpriseOnly = siemErr("SIEM dispatcher requires enterprise build")

type siemErr string

func (e siemErr) Error() string { return string(e) }
