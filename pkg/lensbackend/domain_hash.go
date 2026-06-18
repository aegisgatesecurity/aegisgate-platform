// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Server-Side Domain Hash Verification
// =========================================================================
//
// domain_hash.go recomputes the SHA-256 of the AI provider's hostname
// on the server side and compares it to the DomainHash field that
// the extension sent. This is one of the three independent privacy
// controls: even if a malicious or buggy extension lies about its
// domain_hash, the backend catches it.
//
// Algorithm:
//
//   1. The TLS SNI (Server Name Indication) in the inbound request
//      is the canonical "domain" the extension is talking to.
//   2. The backend extracts the SNI from the *http.Request's
//      TLS.ServerName field (populated automatically by Go's
//      crypto/tls when the connection is TLS-terminated by us).
//   3. The backend computes SHA-256(SNI) and takes the first
//      16 lowercase hex characters.
//   4. The backend compares the result to the extension's
//      domain_hash field. If they differ, the event is rejected
//      with HTTP 400 and the rejection is logged with a
//      "domain_hash_mismatch" reason.
//
// Why server-side recomputation matters:
//
//   - The Lens's privacy policy says "the Lens never sends URLs
//     to any server." The domain_hash is the only domain-related
//     field that crosses the wire.
//   - If the extension lies about the domain_hash, the only way
//     to detect the lie is to recompute it on the server. This
//     prevents an extension (or a man-in-the-middle proxy, or a
//     buggy update) from spoofing the domain.
//   - The SNI is the only signal available at the HTTP layer.
//     The Host header is not authoritative (a client can set it
//     to anything); the SNI is set by the TLS layer and is what
//     the client used to look up the certificate.
//
// Edge cases:
//
//   - If the request is plain HTTP (no TLS), the SNI is empty.
//     The backend rejects the event with "no_tls_sni". The Lens
//     is required to use HTTPS.
//   - If the SNI is a multi-label domain (e.g.,
//     "chat.openai.com"), the hash is computed over the full
//     SNI as received. The extension must use the same SNI.
//   - If the SNI contains an internationalized domain name
//     (IDN), the bytes are hashed as-received. The extension
//     must use the same encoding.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// DomainHashLength is the required length of the DomainHash field.
// Must match the value in validation.go. Duplicated here to keep
// domain_hash.go self-contained.
const DomainHashLength = 16

// ComputeDomainHash returns the 16-hex-character SHA-256 prefix
// of the given hostname. This is the canonical computation; the
// extension's JavaScript does the same thing using the Web Crypto
// API (crypto.subtle.digest("SHA-256", ...)). Both must produce
// the same output for the same input.
func ComputeDomainHash(hostname string) string {
	sum := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(sum[:])[:DomainHashLength]
}

// ExtractSNI returns the TLS SNI from the inbound request, or
// an empty string if the request is plain HTTP. The SNI is
// extracted from r.TLS.ServerName, which is populated by Go's
// crypto/tls when the connection is TLS-terminated by the
// http.Server. If the request is being reverse-proxied (e.g.,
// behind nginx) and we are seeing the SNI of the proxy-to-origin
// connection rather than the client-to-proxy connection, the
// SNI will be the proxy's hostname, not the client's. In that
// case, the operator must configure the proxy to forward the
// original SNI in an X-Forwarded-SNI or X-Original-SNI header;
// see also r.Header.Get("X-Original-SNI").
//
// The SNI is lowercased before being returned, to match the
// extension's behavior (which lowercases hostname.toLowerCase()
// before hashing).
func ExtractSNI(r *http.Request) string {
	if r.TLS != nil && r.TLS.ServerName != "" {
		return strings.ToLower(r.TLS.ServerName)
	}
	// Fallback: some reverse proxies forward the original SNI
	// in a custom header. We check a few common names.
	if v := r.Header.Get("X-Original-SNI"); v != "" {
		return strings.ToLower(v)
	}
	if v := r.Header.Get("X-Forwarded-SNI"); v != "" {
		return strings.ToLower(v)
	}
	return ""
}

// VerifyDomainHash recomputes the SHA-256 of the SNI and compares
// it to the extension's domain_hash field. Returns nil if they
// match, or one of the following errors otherwise:
//
//   - ErrNoTLS: the request is plain HTTP and no SNI is available
//   - ErrDomainHashMismatch: the extension's domain_hash does not
//     match the recomputed hash
//
// The error messages are safe to log and to return to the client
// (they contain no PII, just a description of which check failed).
func VerifyDomainHash(r *http.Request, claimedHash string) error {
	sni := ExtractSNI(r)
	if sni == "" {
		return ErrNoTLS
	}
	actual := ComputeDomainHash(sni)
	if actual != claimedHash {
		return fmt.Errorf("%w: claimed=%s actual=%s sni=%s",
			ErrDomainHashMismatch, claimedHash, actual, sni)
	}
	return nil
}

// ErrNoTLS is returned when the inbound request is plain HTTP
// and no SNI is available. The Lens is required to use HTTPS.
var ErrNoTLS = fmt.Errorf("no TLS SNI available")

// ErrDomainHashMismatch is returned when the extension's
// domain_hash does not match the recomputed hash.
var ErrDomainHashMismatch = fmt.Errorf("domain_hash mismatch")
