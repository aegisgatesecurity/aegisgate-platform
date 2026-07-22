// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST AI 600-1 (GenAI Profile) Module
// =========================================================================
//
// NIST AI 600-1 is the July 2024 Generative AI Profile that accompanies
// NIST AI RMF 1.0. It addresses the 12 unique GenAI risk categories that
// are not covered by the parent AI RMF (confabulation, data privacy,
// model exfiltration, etc.). This is the most relevant framework for
// AegisGate's actual product — we are a GenAI security platform.
//
// Architecture:
//   - nist_ai_600_1.go:       module wiring, 12 RegisterControl calls,
//                            12 CheckFunc implementations
//   - nist_ai_600_1_test.go:  unit tests
//
// Coverage: 12 of 12 GenAI Profile categories (100% in-scope).
// These are the most relevant controls for AegisGate because they
// address exactly the risks that AegisGate mitigates: confabulation,
// prompt injection, model exfiltration, etc.
//
// Reference: NIST AI 600-1 (July 2024)
//            https://www.nist.gov/itl/ai-risk-management-framework
//            Companion to NIST AI RMF 1.0 (January 2023)
//            https://airc.nist.gov/Home
// =========================================================================

package nist_ai_600_1
