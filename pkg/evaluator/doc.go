// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Adversarial Robustness Evals-as-a-Service (AR-EaaS)
//
// Package evaluator implements the AR-EaaS primitive (TODO-301).
// It runs a vendored corpus of MITRE ATLAS adversarial attack
// patterns against a caller-supplied Target, scores pass/fail,
// and signs the result with the attestation envelope.
//
// # Why this exists
//
// The LLM/AI red-team landscape has no canonical, signed primitive
// for "I ran this corpus against this target and got this result."
// AegisGate fills the gap: a customer can run an AegisGate-bundled
// red-team eval against their agent, receive a signed attestation,
// and show the auditor that the agent was tested against a specific
// corpus on a specific date with a specific result.
//
// # What it does
//
//  1. Load a vendored corpus (MITRE ATLAS subset).
//  2. For each AttackPattern, call Target.Answer(prompt).
//  3. Score pass/fail using a per-pattern evaluator function.
//  4. Aggregate results into a RunResult.
//  5. Sign the result with attestation.Sign (envelope primitive).
//
// The signed envelope is portable, third-party-verifiable, and
// tamper-evident. The auditor runs `aegisgate attestation verify`
// to confirm the result is genuine.
//
// # What it does NOT do
//
//   - Run a transformer model. The Target is caller-supplied.
//   - Define a full red-team library. The corpus is a representative
//     subset of MITRE ATLAS tactics, hand-picked for the v0.1 scope.
//   - Replace human red-team engagements. AR-EaaS is a baseline
//     primitive, not a comprehensive solution.
//
// # Usage
//
//	import "github.com/aegisgatesecurity/aegisgate-platform/pkg/evaluator"
//
//	runner := evaluator.NewRunner(corpus, target, keyRing)
//	result, envelope, err := runner.Run(ctx, request)
//
// # Scope (v0.1)
//
//   - 10 attack patterns across 4 MITRE ATLAS tactics
//     (AML.T0018, AML.T0023, AML.T0024, AML.T0048).
//   - 3 severity levels (low, medium, high).
//   - Deterministic: same corpus + same target + same request = same
//     fingerprint.
//   - No network calls. The target is an in-process Go function.
//
// TODO-301. Tier 5. See plans/TODO.md.
package evaluator
