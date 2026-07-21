// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Tier Adapter (Platform ↔ Upstream)
// =========================================================================
//
// Bridges the platform's tier system (pkg/tier) with the upstream
// AegisGate core.Tier and AegisGuard license feature registries. This
// is necessary because the platform, the upstream AegisGate, and
// AegisGuard all maintain their own tier enums and feature strings;
// the adapter is the single place that translates between them.
//
// Why this exists:
//   - pkg/tier has: tier.TierCommunity, tier.TierDeveloper, etc.
//   - upstream/aegisgate/pkg/core has: core.TierCommunity, core.TierDeveloper, etc.
//   - upstream/aegisguard/pkg/license has: aglicense.FeatureXxx strings
//
//   Without the adapter, every consumer of upstream types would need
//   to import all 3 packages and write their own switch statement.
//
// Components:
//   - adapter.go:        tier-to-tier + feature-to-feature mapping
//
// Direction:
//   - Platform -> Upstream (ToAegisGateTier, ToAegisGuardTier)
//   - Upstream -> Platform (FromAegisGateTier, FromAegisGuardTier)
//   - Platform features -> AegisGuard feature strings (FeatureToAegisGuard)
//   - AegisGuard feature strings -> Platform features (FeatureFromAegisGuard)
//
// This package is intentionally small. If it grows past ~300 LOC, that
// is a signal that the 3 tier systems should be consolidated upstream
// (tracked as a refactor task, not in active sprint).
//
// =========================================================================

package tieradapter
