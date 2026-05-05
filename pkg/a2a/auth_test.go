package a2a

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"testing"
)

// helper to create a request with optional TLS state and CN
func newRequestWithCert(commonName string) *http.Request {
	req := &http.Request{}
	if commonName != "" {
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: commonName}}
		// Minimal TLS state with one peer certificate
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	return req
}

func TestMTLSAuth(t *testing.T) {
	auth := &MTLSAuth{}

	t.Run("happy path", func(t *testing.T) {
		r := newRequestWithCert("agent-123")
		id, err := auth.Authenticate(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "agent-123" {
			t.Fatalf("expected ID 'agent-123', got %s", id)
		}
	})

	t.Run("missing cert", func(t *testing.T) {
		r := &http.Request{} // TLS nil
		_, err := auth.Authenticate(r)
		if err == nil {
			t.Fatalf("expected error for missing cert, got nil")
		}
	})

	t.Run("missing CN", func(t *testing.T) {
		// cert with empty CommonName
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: ""}}
		r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
		_, err := auth.Authenticate(r)
		if err == nil {
			t.Fatalf("expected error for missing common name, got nil")
		}
	})
}
