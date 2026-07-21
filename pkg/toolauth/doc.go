// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Tool Authorization Risk Matrix
// =========================================================================
//
// Policy-driven authorization engine that evaluates tool calls against
// configured policies and rules. Computes risk scores, enforces
// approval requirements, and produces authorization decisions for
// every tool invocation within the AegisGate platform.
//
// The matrix is a port of the AegisGuard Tool Authorizer risk matrix,
// adapted for the unified AegisGate platform. v1.3.x was the first
// version; v3.4.0+ extends it with the Trust Framework hooks
// (per-agent trust scores feed into the risk score).
//
// Components:
//   - matrix.go:            core risk matrix + policy evaluation engine
//   - policy.go:            policy DSL (allow/deny/require_approval rules)
//   - decision.go:          authorization decision (ALLOW/BLOCK/REQUIRE_APPROVAL)
//   - coverage_test.go:     risk matrix coverage tests
//
// Risk Score Calculation (weighted factors):
//   - Tool risk:            0-100 based on tool category (read=10, write=50, exec=80)
//   - Agent trust score:    0-100 from pkg/trust (Trust Framework)
//   - Policy match:         0 if matches default_allow, +30 if high_risk, +60 if blocked
//   - Tenant context:       +20 if cross-tenant access (IsAdmin=false)
//
// Final verdict:
//   - 0-30:   ALLOW
//   - 30-70:  REQUIRE_APPROVAL (audit log + human-in-the-loop)
//   - 70-100: BLOCK
//
// Tier gating:
//   - Basic matrix: all tiers
//   - Custom policies:    Professional+
//   - Per-tenant matrix:  Enterprise
//
// =========================================================================

package toolauth
