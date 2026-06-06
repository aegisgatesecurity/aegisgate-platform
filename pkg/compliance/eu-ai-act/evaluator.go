// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform
// =========================================================================
//
// EU AI Act Compliance Module - Evaluator (v3.3.0 Phase 1)
//
// EvaluateEUAIAct is the public API used by the Compliance Scan Engine
// to run the EU AI Act controls against a request payload. The payload
// is typically a configuration dump or proxy capture.
//
// Gating (tier + module ownership) is handled by the caller via
// pkg/compliance.EvaluateGating - the EU AI Act sub-package does NOT
// import the local pkg/compliance package to avoid an import cycle
// (the local pkg/compliance imports this sub-package for registration).

package eu_ai_act

import (
	"context"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// EUAIActResult is the structured output of an EU AI Act evaluation.
type EUAIActResult struct {
	Framework         string                           `json:"framework"`
	Enforced          bool                             `json:"enforced"`
	GatingReason      string                           `json:"gatingReason,omitempty"`
	Controls          []*compliance.ControlCheckResult `json:"controls"`
	CompliantCount    int                              `json:"compliantCount"`
	NonCompliantCount int                              `json:"nonCompliantCount"`
	PartialCount      int                              `json:"partialCount"`
	Score             float64                          `json:"score"`
	GeneratedAt       time.Time                        `json:"generatedAt"`
}

// EvaluateEUAIAct runs all EU AI Act controls against the input. It
// assumes gating has already been resolved by the caller (typically
// pkg/compliance.EvaluateGating). The function constructs a fresh
// EUAIModule (cheap, stateless), calls its CheckAll (which runs every
// automated control and returns NotApplicable for the manual ones),
// and packages the results into an EUAIActResult with a compliance
// score (CompliantCount / Total * 100).
func EvaluateEUAIAct(ctx context.Context, request []byte) (*EUAIActResult, error) {
	mod := NewEUAIModule()
	results, err := mod.CheckAll(ctx, request)
	if err != nil {
		return nil, err
	}
	r := &EUAIActResult{
		Framework:   mod.Framework(),
		Enforced:    true,
		Controls:    results,
		GeneratedAt: time.Now().UTC(),
	}
	for _, c := range results {
		switch c.Status {
		case compliance.StatusCompliant:
			r.CompliantCount++
		case compliance.StatusNonCompliant:
			r.NonCompliantCount++
		case compliance.StatusPartial:
			r.PartialCount++
		}
	}
	total := len(results)
	if total > 0 {
		r.Score = float64(r.CompliantCount) / float64(total) * 100.0
	}
	return r, nil
}
