// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - AegisGate Lens Backend (v3.5.0+ Lens Phase 2)
// =========================================================================
//
// Package lensbackend implements the HTTP backend service for the
// AegisGate Lens browser extension. The Lens is a privacy-first
// Chrome extension (Manifest V3) that observes prompts being typed
// into AI providers (ChatGPT, Claude, Gemini, Copilot) and warns
// the user when sensitive data is detected. The backend receives
// the anonymized telemetry (no prompt content, no URL, no page
// content, no user ID), aggregates it into Indicators of Compromise
// (IOCs), and writes those IOCs into the shared pkg/ioc.Store so
// that AegisGate Gateway installations can pick them up and improve
// their detection rules. This is the "closed-loop threat intel"
// that is the strategic moat of the AegisGate Lens.
//
// Privacy boundary (locked, see plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md
// and plans/AEGISGATE-LENS-THREAT-MODEL.md):
//
//   - The Lens never sends prompt content, URLs, page content,
//     or any user-identifying signal. The only fields that cross
//     the wire are enumerated in Event in validation.go.
//   - The default is OFF. The user must explicitly opt in.
//   - The backend is a thin, stateless, TLS-only service. It
//     reuses pkg/ioc for storage, pkg/attestation for IOC
//     signing, pkg/auth for bearer-token auth, pkg/logging for
//     the audit ringbuffer, and the upstream rate limiter for
//     throttling. No new third-party dependencies are introduced.
//   - Raw events are retained for 90 days. Aggregated IOCs are
//     retained indefinitely. The 24-hour anti-abuse cache and
//     24-hour IP geolocation cache are purged by retention.go.
//
// Architecture references:
//   - plans/AEGISGATE-LENS-PIVOT-2026-06-18.md
//   - plans/AEGISGATE-LENS-ARCHITECTURE-v1.md
//   - plans/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md
//   - plans/AEGISGATE-LENS-THREAT-MODEL.md
//   - plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md
//
// Build (as a sub-command of the existing aegisgate-platform binary):
//   go build -o aegisgate-platform ./cmd/aegisgate-platform/
//   ./aegisgate-platform lensbackend --port=9090 --tls-cert=... --tls-key=...
//
// Or as a separate binary (preferred for cleaner deploy boundary):
//   go build -o lensbackend ./cmd/lensbackend/
//   ./lensbackend --port=9090 --tls-cert=... --tls-key=...
//
// Testing:
//   go test -race ./pkg/lensbackend/...            # unit tests
//   LAB_ENABLED=1 go test -tags=lab -v ./pkg/lensbackend/...   # testlab integration
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

// Package lensbackend is the AegisGate Lens HTTP backend service.
package lensbackend
