// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - First-Run Certificate Initializer
// =========================================================================
//
// Generates self-signed CA + server certificates on startup when
// auto_generate is enabled and no certificates exist. Enables
// zero-config TLS for Community tier deployments:
//
//   - First startup:    generates CA cert + server cert in cert_dir
//   - Subsequent runs:  detects existing certs, skips generation
//   - Idempotent:       safe to call repeatedly (won't overwrite)
//
// Certificate parameters:
//   - Algorithm:   ECDSA P-256 (NIST P-256, FIPS 186-4)
//   - CA validity: 10 years
//   - Server validity: 1 year
//   - SANs:        localhost, 127.0.0.1, ::1, configured hostname
//
// Uses the upstream certificate.Manager from upstream/aegisgate/ for
// the actual cryptographic operations. This package is the
// platform-level wiring (decides when to call the manager based on
// platformconfig.TLS.AutoGenerate + CertDir).
//
// =========================================================================

package certinit
