// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Posture Digest (TODO-601 + TODO-602)
//
// Package digest is the CISO Posture Digest: a
// branded, regulator-acceptable PDF report that
// summarizes the platform's security posture over
// a period (daily/weekly/monthly). It is the
// primary artifact the CISO hands to auditors,
// boards, and customers.
//
// What v0.1 ships:
//
//   - Digest struct (Period, IOCsBlocked,
//     AnomaliesDetected, Posture, RegulatorMappings,
//     TopSources, TopThreats, GeneratedAt, etc.)
//   - Source interface + 3 adapters (PostureSource,
//     IOCSource, AuditSource)
//   - BuildDigest (TODO-602; the producer)
//   - RenderDigestPDF (TODO-601; the consumer)
//   - SignDigest (uses pkg/attestation envelope)
//   - VerifyDigest (verifies the signed digest)
//   - CLI: aegisgate digest generate / verify / list
//   - HTTP: POST /api/v1/digest/{generate,verify}
//     (Professional+ tier gated for publish)
//
// What v0.1 does NOT ship:
//
//   - Real-time streaming of digest updates
//   - Webhook delivery
//   - Multi-tenant isolation
//   - Custom branding per customer
//   - Real-time aggregations (the IOC / audit
//     breakdowns are populated in v0.2)
package digest
