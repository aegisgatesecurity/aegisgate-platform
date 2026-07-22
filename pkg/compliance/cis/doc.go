// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CIS Critical Security Controls v8 Module
// =========================================================================
//
// CIS Critical Security Controls v8 (formerly SANS Top 20) is the
// de-facto industry baseline for US enterprise security questionnaires.
// Appears in 80%+ of enterprise RFPs.
//
// Architecture:
//   - cis.go:        module wiring, 10 RegisterControl calls,
//                    10 CheckFunc implementations
//   - cis_test.go:   unit tests
//
// Coverage: 10 of 18 CIS v8 control families mapped to AegisGate. The
// remaining 8 (Application Software Security, Penetration Testing, etc.)
// are either out-of-scope for a security gateway or duplicate the
// NIST CSF 2.0 controls (which we map separately).
//
// Tier & pricing:
//   - Required tier:  Community (free, bundled with the platform)
//   - Module key:     "cis" (no license gate; this is a free community framework)
//
// Reference: https://www.cisecurity.org/controls/cis-controls-list
//            CIS Critical Security Controls v8.0 (May 2024)
// =========================================================================

package cis
