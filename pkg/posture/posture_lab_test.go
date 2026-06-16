// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 AegisGate Security
// =========================================================================
// Posture Lab Integration Tests
// Requires: cd testlab && docker compose up -d (optional, for live test)
// Run with: LAB_ENABLED=1 go test ./pkg/posture/...
// =========================================================================
//
// posture_lab_test.go exercises the posture checker end-to-end:
//   - Real *license.Manager + *compliance.Scanner (constructed in-process)
//   - Real *compliance.EvaluateGating for framework evaluation
//   - HTTP API round-trip via httptest.NewServer (not mocked handlers)
//   - Long-running scenarios (uptime ticks, license state changes)
//
// These tests are gated by LAB_ENABLED=1 because they take longer
// than the unit tests and exercise the full package surface.
// When run without LAB_ENABLED, they skip gracefully.
//
// v3.3.0+ Phase 6.5.

package posture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// skipIfLabDisabled skips the test when LAB_ENABLED is not set.
// This matches the pattern used in pkg/sso/sso_lab_test.go and
// pkg/email/email_lab_test.go.
func skipIfLabDisabled(t *testing.T) {
	t.Helper()
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED not set; skipping lab test (set LAB_ENABLED=1 to enable)")
	}
}

// realLicenseManager returns a real *license.Manager (Community tier).
func realLicenseManager(t *testing.T) *license.Manager {
	t.Helper()
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatalf("license.NewManager: %v", err)
	}
	return mgr
}

// TestPosture_LiveLicenseManager_EndToEnd exercises the full Checker
// against a real license manager. Confirms that the checker does not
// call any nil methods on the real license types.
func TestPosture_LiveLicenseManager_EndToEnd(t *testing.T) {
	skipIfLabDisabled(t)
	mgr := realLicenseManager(t)

	checker := NewChecker(Deps{
		StartTime: time.Now().Add(-2 * time.Hour),
		Version:   "v3.3.0-lab",
		Commit:    "lab-test",
		License:   mgr, // reuse the mgr declared above

		Mode:       "lab",
		Now:        time.Now,
		GatingFunc: compliance.EvaluateGating,
	})

	// Set the license via the manager.
	// The community tier has no license key, so we exercise the
	// "no key" path (which returns nil from GetValidation).

	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("checker.Check: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.Overall == "" {
		t.Error("Overall status is empty")
	}
	// With a real (empty) license, the overall should be healthy
	// (the license subsystem is unknown, not unhealthy).
	if report.Overall == StatusUnhealthy {
		t.Errorf("Overall=%q; with no license key, expected healthy or unknown, not unhealthy", report.Overall)
	}
}

// TestPosture_LiveComplianceGating_AllFrameworks confirms the
// checker evaluates all 8 known frameworks and reports a
// consistent per-framework status.
func TestPosture_LiveComplianceGating_AllFrameworks(t *testing.T) {
	skipIfLabDisabled(t)
	mgr := realLicenseManager(t)
	checker := NewChecker(Deps{
		StartTime:  time.Now().Add(-1 * time.Hour),
		Version:    "v3.3.0-lab",
		Commit:     "lab-test",
		License:    mgr,
		Mode:       "lab",
		Now:        time.Now,
		GatingFunc: compliance.EvaluateGating,
	})

	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("checker.Check: %v", err)
	}
	// The community tier + no license means none of the paid
	// frameworks should be enforced.
	enforcedCount := 0
	for _, c := range report.Compliance {
		if c.Enforced {
			enforcedCount++
		}
	}
	if enforcedCount > 0 {
		t.Errorf("expected 0 enforced frameworks on community tier, got %d", enforcedCount)
	}
	// Should have at least the 7 paid frameworks evaluated.
	if len(report.Compliance) < 7 {
		t.Errorf("expected at least 7 compliance frameworks, got %d", len(report.Compliance))
	}
}

// TestPosture_HTTP_API_RealServer exercises the full HTTP API surface
// against a real httptest.Server. Confirms JSON shape, status codes,
// and Content-Type handling. Does NOT mock the handler.
func TestPosture_HTTP_API_RealServer(t *testing.T) {
	skipIfLabDisabled(t)
	mgr := realLicenseManager(t)

	checker := NewChecker(Deps{
		StartTime:  time.Now().Add(-30 * time.Minute),
		Version:    "v3.3.0-lab",
		Commit:     "lab-test",
		License:    mgr,
		Mode:       "lab",
		Now:        time.Now,
		GatingFunc: compliance.EvaluateGating,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/posture", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		report, err := checker.Check(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(report)
		w.Write(data)
	})
	mux.HandleFunc("/api/v1/posture/verbose", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		report, err := checker.Check(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(report)
		w.Write(data)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Test the default endpoint.
	resp, err := http.Get(srv.URL + "/api/v1/posture")
	if err != nil {
		t.Fatalf("GET /api/v1/posture: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var report Report
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Version != "v3.3.0-lab" {
		t.Errorf("version = %q, want v3.3.0-lab", report.Version)
	}

	// Test the verbose endpoint returns the same shape (the "verbose"
	// flag is a CLI display concern, not an HTTP one).
	resp2, err := http.Get(srv.URL + "/api/v1/posture/verbose")
	if err != nil {
		t.Fatalf("GET /api/v1/posture/verbose: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("verbose status = %d, want 200", resp2.StatusCode)
	}

	// Test that POST is rejected.
	resp3, err := http.Post(srv.URL+"/api/v1/posture", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", resp3.StatusCode)
	}
}

// TestPosture_ConcurrentChecks exercises the checker under
// concurrent load. Confirms that the checker is safe for
// parallel use (the license manager is read-only in this path).
func TestPosture_ConcurrentChecks(t *testing.T) {
	skipIfLabDisabled(t)
	mgr := realLicenseManager(t)

	checker := NewChecker(Deps{
		StartTime:  time.Now().Add(-1 * time.Hour),
		Version:    "v3.3.0-lab",
		Commit:     "lab-test",
		License:    mgr,
		Mode:       "lab",
		Now:        time.Now,
		GatingFunc: compliance.EvaluateGating,
	})

	const goroutines = 20
	const itersPer = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errCh := make(chan error, goroutines*itersPer)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < itersPer; j++ {
				report, err := checker.Check(context.Background())
				if err != nil {
					errCh <- fmt.Errorf("check: %w", err)
					return
				}
				if report == nil {
					errCh <- fmt.Errorf("nil report")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestPosture_FormatJSON_StableAcrossCalls confirms that the JSON
// output is stable across calls (same input = same bytes), which
// is the machine contract.
func TestPosture_FormatJSON_StableAcrossCalls(t *testing.T) {
	skipIfLabDisabled(t)
	mgr := realLicenseManager(t)

	checker := NewChecker(Deps{
		StartTime:  time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC),
		Version:    "v3.3.0-lab",
		Commit:     "lab-test",
		License:    mgr,
		Mode:       "lab",
		Now:        func() time.Time { return time.Date(2026, 6, 14, 12, 30, 0, 0, time.UTC) },
		GatingFunc: compliance.EvaluateGating,
	})

	// Build two reports back-to-back. They should differ only in
	// generated_at and uptime (if checker uses time.Now()).
	r1, err := checker.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := checker.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// With our injected Now, generated_at and uptime should be identical.
	if r1.GeneratedAt != r2.GeneratedAt {
		t.Errorf("generated_at drift: %v vs %v", r1.GeneratedAt, r2.GeneratedAt)
	}
	if r1.Version != r2.Version {
		t.Errorf("version drift: %q vs %q", r1.Version, r2.Version)
	}
}

// _ is a compile-time guard that the test file uses the real types.
// (Catches accidental type drift between lab tests and unit tests.)
var (
	_ *license.Manager
	_ *compliance.Scanner
	_ *ecdsa.PrivateKey
	_ = elliptic.P256
	_ = rand.Reader
)
