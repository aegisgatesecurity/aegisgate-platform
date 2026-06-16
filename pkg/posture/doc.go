// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Posture Check (v3.3.0 Phase 6.5)
// =========================================================================
//
// Package posture produces a single-source-of-truth "is your AegisGate
// doing what you think it is doing?" health summary. It is the
// founder-facing install story and the operator-level signal that
// closes the gap between:
//   - the Trust Framework (developer-level signal)
//   - the public trust page (marketing-level signal)
//   - the on-call runbook (operator-level signal)
//
// # Design Principles
//
//   - Read-only. Posture check NEVER mutates state.
//   - Fail-closed in *display*: an unhealthy subsystem is shown as such,
//     never silently masked.
//   - Composable. The Checker accepts injected dependencies so the
//     posture check can be tested with stub data.
//   - Two output modes: default (plain text, non-technical operator) and
//     verbose (JSON, technical operator with full subsystem detail).
//   - No new network calls. Posture reads only in-process state that
//     is already kept up to date by the existing subsystems.
//
// # Example
//
//	checker := posture.NewChecker(posture.Deps{
//	    License:     licenseMgr,
//	    StartTime:   startTime,
//	    Version:     version,
//	})
//	report, err := checker.Check(ctx)
//	if err != nil {
//	    log.Fatalf("posture check failed: %v", err)
//	}
//	fmt.Println(posture.FormatText(report))   // human-readable
//	data, _ := posture.FormatJSON(report)      // machine-readable
//
// # Tier Gating
//
// The posture check itself is FREE for all tiers (Community+). It is
// the operator's health summary and should not be paywalled.
//
// v3.3.0 Phase 6.5.
package posture
