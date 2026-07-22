// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CSA STAR (Cloud Controls Matrix) Module
// =========================================================================
//
// CSA STAR (Security, Trust, Assurance, and Risk) is the Cloud Security
// Alliance's framework for cloud security assurance. Required for SaaS
// enterprise sales and is the de facto cloud security certification.
//
// Architecture:
//   - csa_star.go:       module wiring, 16 RegisterControl calls,
//                        16 CheckFunc implementations
//   - csa_star_test.go:  unit tests
//
// Coverage: 16 of 16 CCM domains (100% in-scope).
// All 16 domains are scanner-checkable through the same pattern as
// the other v3.x modules.
//
// Reference: CSA Cloud Controls Matrix v4.0
//            https://cloudsecurityalliance.org/research/cloud-controls-matrix/
// =========================================================================

package csa_star
