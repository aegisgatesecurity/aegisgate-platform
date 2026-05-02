// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SAML Mock HTTP Servers for Testing
// =========================================================================

package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"
)

// MockSAMLServer creates a mock SAML IdP server
type MockSAMLServer struct {
	Server      *httptest.Server
	MetadataURL string
	SSOURL      string
	SLOURL      string
	EntityID    string
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// NewMockSAMLServer creates a mock SAML IdP server
func NewMockSAMLServer() (*MockSAMLServer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test IdP"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	m := &MockSAMLServer{
		EntityID:    "https://test-idp.example.com",
		Certificate: cert,
		PrivateKey:  priv,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", m.handleMetadata)
	mux.HandleFunc("/sso", m.handleSSO)
	mux.HandleFunc("/slo", m.handleSLO)
	mux.HandleFunc("/acs", m.handleACS) // Assertion Consumer Service endpoint

	m.Server = httptest.NewServer(mux)
	m.MetadataURL = m.Server.URL + "/metadata"
	m.SSOURL = m.Server.URL + "/sso"
	m.SLOURL = m.Server.URL + "/slo"

	return m, nil
}

// Close shuts down the mock server
func (m *MockSAMLServer) Close() {
	m.Server.Close()
}

// handleMetadata returns SAML IdP metadata
func (m *MockSAMLServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	certPEM := base64.StdEncoding.EncodeToString(m.Certificate.Raw)

	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>`,
		m.EntityID, certPEM, m.SSOURL, m.SLOURL)

	w.Header().Set("Content-Type", "application/xml")
	if _, err := w.Write([]byte(metadata)); err != nil {
		return
	}
}

// handleSSO handles SAML authentication requests
func (m *MockSAMLServer) handleSSO(w http.ResponseWriter, r *http.Request) {
	samlRequest := r.URL.Query().Get("SAMLRequest")
	if samlRequest == "" {
		http.Error(w, "SAMLRequest required", http.StatusBadRequest)
		return
	}

	relayState := r.URL.Query().Get("RelayState")
	// Redirect to mock server's ACS URL, not localhost
	acsURL := m.Server.URL + "/acs"

	samlResponse := m.buildSAMLResponse(acsURL, relayState)
	redirectURL := fmt.Sprintf("%s?SAMLResponse=%s", acsURL, base64.StdEncoding.EncodeToString([]byte(samlResponse)))

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleSLO handles SAML logout requests
func (m *MockSAMLServer) handleSLO(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// handleACS handles the Assertion Consumer Service endpoint
func (m *MockSAMLServer) handleACS(w http.ResponseWriter, r *http.Request) {
	// Just acknowledge receipt - don't redirect further
	w.WriteHeader(http.StatusOK)
}

// buildSAMLResponse creates a SAML Response
func (m *MockSAMLServer) buildSAMLResponse(acsURL, relayState string) string {
	now := time.Now().UTC()
	instant := now.Format(time.RFC3339)
	responseID := fmt.Sprintf("_%x", generateRandomBytes(16))

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s" Version="2.0" IssueInstant="%s" Destination="%s">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">%s</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_%x" Version="2.0" IssueInstant="%s">
        <saml:Issuer>%s</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction><saml:Audience>http://localhost</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="%s" SessionIndex="test-session-index">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="email"><saml:AttributeValue>testuser@example.com</saml:AttributeValue></saml:Attribute>
            <saml:Attribute Name="groups"><saml:AttributeValue>users</saml:AttributeValue><saml:AttributeValue>developers</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`,
		responseID, instant, acsURL, m.EntityID,
		generateRandomBytes(16), instant, m.EntityID,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		instant)
}

// generateRandomBytes generates random bytes for IDs
func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// NewSAMLConfig creates a SAML config for use with mock server
func (m *MockSAMLServer) NewSAMLConfig() *SSOConfig {
	return &SSOConfig{
		Provider: ProviderSAML,
		Name:     "test-saml",
		SAML: &SAMLConfig{
			EntityID:    m.Server.URL,
			ACSURL:      m.Server.URL + "/acs",
			IDPEntityID: m.EntityID,
			IDPSSODescriptor: &IDPSSODescriptor{
				SSOURLs:             []string{m.SSOURL},
				SLOURLs:             []string{m.SLOURL},
				SigningCertificates: []*x509.Certificate{m.Certificate},
			},
		},
	}
}

// GetMetadataBytes fetches metadata from mock server
func (m *MockSAMLServer) GetMetadataBytes() ([]byte, error) {
	resp, err := http.Get(m.MetadataURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
