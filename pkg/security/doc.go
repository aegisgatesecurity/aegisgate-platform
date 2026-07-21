// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Security Middleware
// =========================================================================
//
// HTTP security middleware: security headers, CORS, request limits.
// Applied to every HTTP response by APIHeadersMiddleware (mounted in
// cmd/aegisgate-platform/main.go on both proxyMux and dashMux).
//
// Security Headers (always set by default, configurable via SecurityConfig):
//   - Content-Security-Policy:    default 'none' (strictest)
//   - X-Frame-Options:            DENY (clickjacking protection)
//   - X-Content-Type-Options:     nosniff (MIME-type sniffing protection)
//   - X-XSS-Protection:           1; mode=block (legacy XSS auditor)
//   - Referrer-Policy:            no-referrer or strict-origin-when-cross-origin
//   - Strict-Transport-Security:  max-age=31536000; includeSubDomains (HSTS)
//   - Cross-Origin-Resource-Policy: same-origin
//   - Server:                     DELETED (no platform banner leakage)
//
// Note: 'Server: cloudflare' and 'Cf-Ray' headers may appear on local
// development hosts running Cloudflare WARP in Gateway mode (WARP
// rewrites 4xx responses). These are NOT from the platform — see
// audit-lab/audit-results/F-CLOUDFLARE-1-RESOLVED.md for details.
//
// CORS (configurable via SecurityConfig.AllowedOrigins/Methods/Headers):
//   - By default: empty AllowedOrigins = no CORS (same-origin only)
//   - When configured: adds Access-Control-Allow-* headers
//
// Request size limits:
//   - MaxBytesHandler (10MB by default, configurable via --max-body-size)
//   - F-DOS-1 (10MB POST DoS) was fixed in D28: 1,206x speedup
//
// =========================================================================

package security
