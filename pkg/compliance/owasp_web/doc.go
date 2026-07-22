// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - OWASP Top 10 Web (2021) Module
// =========================================================================
//
// OWASP Top 10 Web is the de-facto industry baseline for web application
// security. Completes the OWASP coverage story (we already have OWASP
// LLM Top 10 for AI-specific threats; this adds the Web layer).
//
// Architecture:
//   - owasp_web.go:        module wiring, 10 RegisterControl calls,
//                          10 CheckFunc implementations
//   - owasp_web_test.go:   unit tests
//
// Coverage: 10 of 10 OWASP Top 10 Web categories (A01-A10) mapped to
// AegisGate. Each control has at least 1 automated CheckFunc.
//
// Tier & pricing:
//   - Required tier:  Community (free, bundled with the platform)
//   - Module key:     "owasp_web"
//
// Reference: https://owasp.org/Top10/
//            OWASP Top 10:2021 (September 2021)
// =========================================================================

package owasp_web
