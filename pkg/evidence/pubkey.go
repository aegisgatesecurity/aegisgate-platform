// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.4.0+)
//
// pubkey.go provides the canonical public key fetch primitive
// for the AegisGate evidence-signing key. This is the missing
// piece of the verifiable compliance workflow: an auditor can
// fetch the platform's evidence-signing public key from a
// well-known URL, then use it to verify any manifest without
// needing access to the platform's private state.
//
// The endpoint is:
//
//	GET /.well-known/aegisgate-evidence-pubkey.pem
//
// It returns the SEC 1 encoded ECDSA P-256 public key, wrapped
// in a standard PEM "PUBLIC KEY" block. The same key is
// embedded in the Manifest.Signature.PublicKey field for
// convenience, but the well-known URL is the authoritative
// source: if the embedded key differs from the well-known key,
// the auditor should refuse the manifest and alert the CISO.
//
// v3.4.0+ (this is the c3 deliverable that closes the
// verifiable compliance primitive loop).

package evidence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
)

// PEM block type for the evidence public key. Standard PKIX
// format - any tool that handles ECDSA P-256 public keys
// (openssl, keytool, jwt libraries) can parse it.
const pubKeyPEMType = "PUBLIC KEY"

// PublicKeyPEM returns the canonical PEM encoding of the
// platform's evidence-signing public key. The key is the
// one passed to the Builder at construction time.
//
// The returned bytes are a standard PEM block:
//
//	-----BEGIN PUBLIC KEY-----
//	<base64 DER>
//	-----END PUBLIC KEY-----
//
// Auditors fetch this from /.well-known/aegisgate-evidence-pubkey.pem
// and use it to verify any manifest produced by this platform.
func PublicKeyPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("evidence: nil public key")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("evidence: public key is not P-256 (got %v)", pub.Curve.Params().Name)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal PKIX public key: %w", err)
	}
	block := &pem.Block{
		Type:  pubKeyPEMType,
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// WellKnownHandler returns an http.Handler that serves the
// evidence public key at the canonical well-known URL. The
// returned handler is intended to be mounted at the root of
// the HTTP server, NOT under /api/v1/.
//
// Mounting example:
//
//	mux.Handle("/.well-known/aegisgate-evidence-pubkey.pem", pubHandler)
//
// The handler returns the PEM-encoded public key with
// Content-Type: application/x-pem-file. If the key is
// missing or malformed, it returns 503 Service Unavailable -
// the evidence subsystem is enabled, so the operator must
// have a valid key. (This is distinct from a 404: the
// evidence subsystem is configured but cannot serve the key.)
func WellKnownHandler(pub *ecdsa.PublicKey) (http.Handler, error) {
	pemBytes, err := PublicKeyPEM(pub)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Cache-Control", "public, max-age=300") // 5 min - key rotates rarely
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(pemBytes)
	}), nil
}
