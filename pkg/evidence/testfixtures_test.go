// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Test Fixtures (v3.3.0+)
//
// testfixtures_test.go provides shared test fixtures for the
// compliance test suite (unit + lab). The fixtures are designed
// to be USED, not inspected - callers should treat them as
// "give me a real, fully-wired Scanner/Registry/Builder that
// behaves like production".
//
// Design principles:
//   1. Real implementations wherever possible (no mocks of our
//      own code).
//   2. Test doubles only for the common.Framework interface
//      (avoid calling into framework Check() implementations
//      that may have hidden dependencies).
//   3. Each helper is t.Cleanup()-safe and self-contained.
//   4. Helpers are also exported for cross-package test use
//      (e.g., the evidence package can use the compliance
//      fixture helpers).
//
// Reproduce: LAB_ENABLED=1 go test -tags=lab ./...
// Or: bash scripts/run-lab-tests.sh

package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"

	comp "github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// newTestScanner returns a real *comp.Scanner configured for
// a Professional-tier license (which allows all 9 frameworks to
// register). The Scanner uses an empty registry by default; for
// registry-level tests, use newTestRegistry() + comp.NewScanner(reg, opts).
//
// This is the canonical "give me a working Scanner" helper for
// evidence unit tests. It does not require LAB_ENABLED.
func newTestScanner(t *testing.T) *comp.Scanner {
	t.Helper()
	return comp.NewScanner(nil, &comp.ScannerOpts{CacheTTL: time.Minute})
}

// newTestRegistry returns a real *comp.Registry with all 9
// frameworks registered using test-double implementations.
//
// We use test-double framework implementations (fakeFramework
// below) rather than the real ones from pkg/compliance/{hipaa,
// pci,...} for three reasons:
//  1. The real implementations may have hidden dependencies
//     on license keys, external services, or feature flags.
//  2. Test doubles let us control the response shape exactly,
//     making assertions deterministic.
//  3. The real implementations are tested in their own packages.
//
// The registry is set to Premium tier (Tier=2) so all 9 framework
// tiers (Community, Enterprise, Premium) are accessible.
func newTestRegistry(t *testing.T) *comp.Registry {
	t.Helper()
	tm := comp.NewTierManager()
	tm.SetTier(comp.TierPremium)
	reg := comp.NewRegistryWithTierManager(tm)
	// Register each known framework with a test-double implementation.
	for _, id := range knownFrameworkIDs {
		if err := reg.Register(&fakeFramework{frameworkID: id}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	return reg
}

// knownFrameworkIDs is the canonical list of all 9 framework IDs
// registered by the TierManager default initialisation. Kept in
// sync with tier-manager.go:initializeDefaults().
var knownFrameworkIDs = []string{
	"atlas",       // Community
	"owasp",       // Community
	"gdpr",        // Community
	"nist_ai_rmf", // Enterprise
	"nist_1500",   // Enterprise
	"iso42001",    // Enterprise
	"soc2",        // Premium
	"hipaa",       // Premium
	"pci",         // Premium
}

// newTestEvidenceBuilder returns a real *Builder wired with a
// real Scanner, real License manager, real signing key, and a
func newTestEvidenceBuilder(t *testing.T) *Builder {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	ring := logging.NewRingBuffer(1000)
	b, err := NewBuilder(BuilderDeps{
		Scanner:        newTestScanner(t),
		LicenseMgr:     mgr,
		SigningKey:     key,
		KeyID:          "test-fixture-key",
		BuilderVersion: "v3.3.0-testfixture",
		EventSource:    ring,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ring.Clear()
	})
	return b
}

// newRingBufferBackedEventSource returns a real RingBuffer that
// implements the EventSource interface. It is registered to be
// cleared via t.Cleanup().
func newRingBufferBackedEventSource(t *testing.T) *logging.RingBuffer {
	t.Helper()
	ring := logging.NewRingBuffer(1000)
	t.Cleanup(func() { ring.Clear() })
	return ring
}

// fakeFramework is a test double for common.Framework. It returns
// deterministic, realistic-shaped responses for every method.
// It does not require any external dependencies (license,
// database, network).
type fakeFramework struct {
	frameworkID string
	enabled     bool
}

func (f *fakeFramework) GetName() string        { return f.frameworkID + " (test)" }
func (f *fakeFramework) GetVersion() string     { return "v1.0.0-test" }
func (f *fakeFramework) GetDescription() string { return "Test-double " + f.frameworkID }
func (f *fakeFramework) GetFrameworkID() string { return f.frameworkID }
func (f *fakeFramework) GetPatternCount() int   { return 10 }
func (f *fakeFramework) GetSeverityLevels() []common.Severity {
	return []common.Severity{common.SeverityLow, common.SeverityMedium, common.SeverityHigh}
}
func (f *fakeFramework) IsEnabled() bool                          { return f.enabled }
func (f *fakeFramework) Enable()                                  { f.enabled = true }
func (f *fakeFramework) Disable()                                 { f.enabled = false }
func (f *fakeFramework) Configure(_ map[string]interface{}) error { return nil }
func (f *fakeFramework) Check(_ context.Context, _ common.CheckInput) (*common.CheckResult, error) {
	return &common.CheckResult{
		Framework:       f.frameworkID,
		Passed:          true,
		Findings:        nil,
		CheckedAt:       time.Now().UTC(),
		Duration:        0,
		TotalPatterns:   10,
		MatchedPatterns: 0,
	}, nil
}
func (f *fakeFramework) CheckRequest(_ context.Context, _ *common.HTTPRequest) ([]common.Finding, error) {
	return nil, nil
}
func (f *fakeFramework) CheckResponse(_ context.Context, _ *common.HTTPResponse) ([]common.Finding, error) {
	return nil, nil
}
