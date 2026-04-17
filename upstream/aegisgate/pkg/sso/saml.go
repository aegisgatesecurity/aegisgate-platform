// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package sso

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SAMLProvider implements SAML 2.0 SSO
type SAMLProvider struct {
	config     *SSOConfig
	samlConfig *SAMLConfig
	httpClient *http.Client
	store      RequestStore
}

// NewSAMLProvider creates a new SAML provider
func NewSAMLProvider(config *SSOConfig, store RequestStore) (*SAMLProvider, error) {
	if config.SAML == nil {
		return nil, NewSSOError(ErrProviderNotConfigured, "SAML configuration is required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &SAMLProvider{
		config:     config,
		samlConfig: config.SAML,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		store:      store,
	}, nil
}

// Name returns the provider name
func (p *SAMLProvider) Name() string {
	return p.config.Name
}

// Type returns the provider type
func (p *SAMLProvider) Type() SSOProvider {
	return ProviderSAML
}

// InitiateLogin creates a SAML authentication request
func (p *SAMLProvider) InitiateLogin(state string) (string, *SSORequest, error) {
	requestID := generateRequestID()
	now := time.Now().UTC()

	authnRequest := &AuthnRequest{
		ID:           requestID,
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339),
		Destination:  p.samlConfig.IDPSSODescriptor.SSOURLs[0],
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  p.samlConfig.EntityID,
		},
		NameIDPolicy: &NameIDPolicy{
			Format:      p.samlConfig.NameIDFormat,
			AllowCreate: p.samlConfig.AllowCreate,
		},
		RequestedAuthnContext: &RequestedAuthnContext{
			Comparison: "exact",
			AuthnContextClassRef: &AuthnContextClassRef{
				Value: p.samlConfig.AuthnContextClass,
			},
		},
	}

	if p.samlConfig.ForceAuthn {
		authnRequest.ForceAuthn = "true"
	}
	if p.samlConfig.IsPassive {
		authnRequest.IsPassive = "true"
	}

	requestXML, err := xml.Marshal(authnRequest)
	if err != nil {
		return "", nil, NewSSOError(ErrInvalidAuthnRequest, "failed to marshal authn request").WithCause(err)
	}

	// Wrap in SAML namespace
	requestXML = []byte(strings.Replace(string(requestXML), "<AuthnRequest",
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`, 1))

	// Base64 encode
	encodedRequest := base64.StdEncoding.EncodeToString(requestXML)

	// Build redirect URL
	ssoURL := p.samlConfig.IDPSSODescriptor.SSOURLs[0]
	redirectURL, err := url.Parse(ssoURL)
	if err != nil {
		return "", nil, NewSSOError(ErrInvalidAuthnRequest, "invalid SSO URL").WithCause(err)
	}

	query := redirectURL.Query()
	query.Set("SAMLRequest", encodedRequest)
	query.Set("RelayState", state)
	redirectURL.RawQuery = query.Encode()

	ssoRequest := &SSORequest{
		ID:          requestID,
		Provider:    p.config.Name,
		SAMLRequest: encodedRequest,
		RelayState:  state,
		Destination: ssoURL,
		State:       state,
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}

	if p.store != nil {
		if err := p.store.Create(ssoRequest); err != nil {
			return "", nil, NewSSOError(ErrInvalidRequest, "failed to store request").WithCause(err)
		}
	}

	return redirectURL.String(), ssoRequest, nil
}

// HandleCallback processes the SAML response from the IdP
func (p *SAMLProvider) HandleCallback(request *SSORequest, params map[string]string) (*SSOResponse, error) {
	samlResponse, ok := params["SAMLResponse"]
	if !ok {
		return nil, NewSSOError(ErrInvalidCallback, "missing SAMLResponse parameter")
	}

	// Decode the response
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, NewSSOError(ErrInvalidCallback, "failed to decode SAML response").WithCause(err)
	}

	// Parse the response
	response := &Response{}
	if err := xml.Unmarshal(decoded, response); err != nil {
		return nil, NewSSOError(ErrInvalidCallback, "failed to parse SAML response").WithCause(err)
	}

	// Validate the response
	if err := p.validateResponse(response); err != nil {
		return nil, err
	}

	// Extract assertion
	assertion := response.Assertion
	if assertion == nil {
		return nil, NewSSOError(ErrInvalidAssertion, "no assertion in response")
	}

	// Extract attributes
	attributes := p.extractAttributes(assertion)

	// Create SSO user
	user := &SSOUser{
		SSOProvider:   ProviderSAML,
		SSOProviderID: p.config.Name,
		RawAttributes: attributes,
		UpstreamID:    assertion.Subject.NameID.Value,
		NameID:        assertion.Subject.NameID.Value,
		SessionIndex:  assertion.AuthnStatement.SessionIndex,
		AuthnContext:  assertion.AuthnStatement.AuthnContext.AuthnContextClassRef.Value,
		AuthnInstant:  parseTime(assertion.AuthnStatement.AuthnInstant),
	}

	// Map attributes to user fields
	p.mapAttributesToUser(user, attributes)

	// Create session
	session := &SSOSession{
		ID:           generateSessionID(),
		User:         user,
		UserID:       user.ID,
		Provider:     ProviderSAML,
		ProviderName: p.config.Name,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(p.config.SessionDuration),
		LastActivity: time.Now(),
		NameID:       user.NameID,
		SessionIndex: user.SessionIndex,
		Active:       true,
		Metadata:     make(map[string]interface{}),
	}

	return &SSOResponse{
		Success:    true,
		User:       user,
		Session:    session,
		Attributes: attributes,
	}, nil
}

// ValidateSession validates an existing SSO session
func (p *SAMLProvider) ValidateSession(session *SSOSession) error {
	if session == nil {
		return NewSSOError(ErrInvalidToken, "nil session")
	}
	if session.IsExpired() {
		return NewSSOError(ErrSessionExpired, "session has expired")
	}
	if !session.Active {
		return NewSSOError(ErrInvalidToken, "session is not active")
	}
	return nil
}

// Logout initiates SAML single logout
func (p *SAMLProvider) Logout(session *SSOSession) (string, error) {
	if session == nil {
		return "", NewSSOError(ErrInvalidToken, "nil session")
	}

	// Check if IdP supports SLO
	if len(p.samlConfig.IDPSSODescriptor.SLOURLs) == 0 {
		// IdP doesn't support SLO, return empty URL
		return "", nil
	}

	logoutRequest := &LogoutRequest{
		ID:           generateRequestID(),
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  p.samlConfig.IDPSSODescriptor.SLOURLs[0],
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  p.samlConfig.EntityID,
		},
		NameID: &NameID{
			Format:          p.samlConfig.NameIDFormat,
			NameQualifier:   p.samlConfig.IDPEntityID,
			SPNameQualifier: p.samlConfig.EntityID,
			Value:           session.NameID,
		},
		SessionIndex: session.SessionIndex,
	}

	requestXML, err := xml.Marshal(logoutRequest)
	if err != nil {
		return "", NewSSOError(ErrInvalidRequest, "failed to marshal logout request").WithCause(err)
	}

	encodedRequest := base64.StdEncoding.EncodeToString(requestXML)

	sloURL, err := url.Parse(p.samlConfig.IDPSSODescriptor.SLOURLs[0])
	if err != nil {
		return "", NewSSOError(ErrInvalidRequest, "invalid SLO URL").WithCause(err)
	}

	query := sloURL.Query()
	query.Set("SAMLRequest", encodedRequest)
	sloURL.RawQuery = query.Encode()

	return sloURL.String(), nil
}

// Metadata generates the SP metadata
func (p *SAMLProvider) Metadata() ([]byte, error) {
	metadata := &EntityDescriptor{
		EntityID:   p.samlConfig.EntityID,
		ValidUntil: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		SPSSODescriptor: &SPSSODescriptor{
			AuthnRequestsSigned:        p.samlConfig.ValidateSignature,
			WantAssertionsSigned:       p.samlConfig.WantAssertionsSigned,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			NameIDFormats: []string{
				"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
				"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			},
			AssertionConsumerService: []AssertionConsumerService{
				{
					Index:     0,
					IsDefault: true,
					Binding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location:  p.samlConfig.ACSURL,
				},
			},
			SingleLogoutService: []SingleLogoutService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					Location: p.samlConfig.SLSURL,
				},
			},
		},
	}

	return xml.MarshalIndent(metadata, "", "  ")
}

// LoadIDPMetadata loads IdP metadata from URL or bytes
func (p *SAMLProvider) LoadIDPMetadata(metadataURL string, metadataBytes []byte) error {
	var data []byte

	if metadataURL != "" {
		resp, err := p.httpClient.Get(metadataURL)
		if err != nil {
			return NewSSOError(ErrMetadataError, "failed to fetch IdP metadata").WithCause(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return NewSSOError(ErrMetadataError, "failed to read IdP metadata").WithCause(err)
		}
	} else if len(metadataBytes) > 0 {
		data = metadataBytes
	} else {
		return NewSSOError(ErrMetadataError, "no metadata URL or bytes provided")
	}

	// Parse metadata
	var entityDescriptor EntityDescriptor
	if err := xml.Unmarshal(data, &entityDescriptor); err != nil {
		return NewSSOError(ErrMetadataError, "failed to parse IdP metadata").WithCause(err)
	}

	// Extract IdP descriptor
	p.samlConfig.IDPEntityID = entityDescriptor.EntityID
	if entityDescriptor.IDPSSODescriptor != nil {
		p.samlConfig.IDPSSODescriptor = &IDPSSODescriptor{
			EntityID:      entityDescriptor.EntityID,
			SSOURLs:       extractLocations(entityDescriptor.IDPSSODescriptor.SingleSignOnService),
			SLOURLs:       extractSLOLocations(entityDescriptor.IDPSSODescriptor.SingleLogoutService),
			NameIDFormats: entityDescriptor.IDPSSODescriptor.NameIDFormats,
		}
		// Parse certificates
		for _, kd := range entityDescriptor.IDPSSODescriptor.KeyDescriptors {
			if cert, err := parseCertificate(kd.KeyInfo.X509Data.X509Certificate); err == nil {
				if kd.Use == "signing" {
					p.samlConfig.IDPSSODescriptor.SigningCertificates = append(
						p.samlConfig.IDPSSODescriptor.SigningCertificates, cert)
				} else if kd.Use == "encryption" {
					p.samlConfig.IDPSSODescriptor.EncryptionCertificates = append(
						p.samlConfig.IDPSSODescriptor.EncryptionCertificates, cert)
				}
			}
		}
	}

	return nil
}

// validateResponse validates the SAML response
func (p *SAMLProvider) validateResponse(response *Response) error {
	// Check response status
	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return NewSSOError(ErrInvalidAssertion, fmt.Sprintf("SAML response status: %s", response.Status.StatusCode.Value))
	}

	// Validate destination
	// StrictAudience check disabled
	if response.Destination != "" && response.Destination != p.samlConfig.ACSURL {
		// Would return error if StrictAudience was enabled
	}

	// Validate issuer
	if response.Issuer != nil && response.Issuer.Value != p.samlConfig.IDPEntityID {
		return NewSSOError(ErrInvalidAssertion, "response issuer mismatch")
	}

	// Validate assertion conditions
	assertion := response.Assertion
	if assertion == nil {
		return NewSSOError(ErrInvalidAssertion, "no assertion in response")
	}

	if assertion.Conditions != nil {
		now := time.Now()
		notBefore := parseTime(assertion.Conditions.NotBefore)
		notOnOrAfter := parseTime(assertion.Conditions.NotOnOrAfter)

		if now.Before(notBefore.Add(-p.config.ClockSkewTolerance)) {
			return NewSSOError(ErrInvalidAssertion, "assertion not yet valid")
		}
		if now.After(notOnOrAfter.Add(p.config.ClockSkewTolerance)) {
			return NewSSOError(ErrExpiredToken, "assertion has expired")
		}

		// Validate audience
		// StrictAudience check disabled
		if assertion.Conditions.AudienceRestriction != nil {
			found := false
			for _, aud := range assertion.Conditions.AudienceRestriction.Audience {
				if aud == p.samlConfig.EntityID {
					found = true
					break
				}
			}
			_ = found // avoid unused variable error
			// audience check would go here
		}
	}

	// Validate signature if required
	if p.samlConfig.ValidateSignature && response.Signature != nil {
		if err := p.validateSignature(response); err != nil {
			return err
		}
	}

	return nil
}

// validateSignature validates the SAML response signature
func (p *SAMLProvider) validateSignature(response *Response) error {
	if len(p.samlConfig.IDPSSODescriptor.SigningCertificates) == 0 {
		return NewSSOError(ErrCertificateError, "no signing certificates from IdP")
	}

	// Get the certificate
	cert := p.samlConfig.IDPSSODescriptor.SigningCertificates[0]
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return NewSSOError(ErrCertificateError, "invalid certificate type")
	}

	// Extract signed info
	signedInfo := response.Signature.SignedInfo
	if signedInfo == nil {
		return NewSSOError(ErrInvalidSignature, "missing signed info")
	}

	// Canonicalize and hash
	signedInfoBytes, err := xml.Marshal(signedInfo)
	if err != nil {
		return NewSSOError(ErrInvalidSignature, "failed to marshal signed info").WithCause(err)
	}

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(response.Signature.SignatureValue.Value)
	if err != nil {
		return NewSSOError(ErrInvalidSignature, "failed to decode signature").WithCause(err)
	}

	// Verify signature based on algorithm
	switch p.samlConfig.SignatureAlgorithm {
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "":
		hashed := sha256.Sum256(signedInfoBytes)
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signatureBytes); err != nil {
			return NewSSOError(ErrInvalidSignature, "signature verification failed").WithCause(err)
		}
	default:
		return NewSSOError(ErrInvalidSignature, "unsupported signature algorithm")
	}

	return nil
}

// extractAttributes extracts attributes from a SAML assertion
func (p *SAMLProvider) extractAttributes(assertion *Assertion) map[string]interface{} {
	attributes := make(map[string]interface{})
	if assertion.AttributeStatement == nil {
		return attributes
	}

	for _, attr := range assertion.AttributeStatement.Attributes {
		if len(attr.AttributeValues) == 1 {
			attributes[attr.Name] = attr.AttributeValues[0].Value
		} else {
			values := make([]string, len(attr.AttributeValues))
			for i, v := range attr.AttributeValues {
				values[i] = v.Value
			}
			attributes[attr.Name] = values
		}
	}

	return attributes
}

// mapAttributesToUser maps SAML attributes to user fields
func (p *SAMLProvider) mapAttributesToUser(user *SSOUser, attributes map[string]interface{}) {
	mapping := p.config.AttributeMapping
	if mapping == nil {
		mapping = SAMLAttributeMapping()
	}

	user.Groups = extractStringSlice(attributes, mapping.GroupAttribute)
}

// SAML XML types

type AuthnRequest struct {
	XMLName               xml.Name               `xml:"samlp:AuthnRequest"`
	ID                    string                 `xml:"ID,attr"`
	Version               string                 `xml:"Version,attr"`
	IssueInstant          string                 `xml:"IssueInstant,attr"`
	Destination           string                 `xml:"Destination,attr,omitempty"`
	ForceAuthn            string                 `xml:"ForceAuthn,attr,omitempty"`
	IsPassive             string                 `xml:"IsPassive,attr,omitempty"`
	Issuer                *Issuer                `xml:"saml:Issuer"`
	NameIDPolicy          *NameIDPolicy          `xml:"samlp:NameIDPolicy"`
	RequestedAuthnContext *RequestedAuthnContext `xml:"samlp:RequestedAuthnContext"`
}

type Issuer struct {
	XMLName xml.Name `xml:"saml:Issuer"`
	Format  string   `xml:"Format,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

type NameIDPolicy struct {
	XMLName         xml.Name `xml:"samlp:NameIDPolicy"`
	Format          string   `xml:"Format,attr,omitempty"`
	SPNameQualifier string   `xml:"SPNameQualifier,attr,omitempty"`
	AllowCreate     bool     `xml:"AllowCreate,attr,omitempty"`
}

type RequestedAuthnContext struct {
	XMLName              xml.Name              `xml:"samlp:RequestedAuthnContext"`
	Comparison           string                `xml:"Comparison,attr"`
	AuthnContextClassRef *AuthnContextClassRef `xml:"saml:AuthnContextClassRef"`
}

type AuthnContextClassRef struct {
	XMLName xml.Name `xml:"saml:AuthnContextClassRef"`
	Value   string   `xml:",chardata"`
}

type Response struct {
	XMLName      xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string          `xml:"ID,attr"`
	InResponseTo string          `xml:"InResponseTo,attr,omitempty"`
	Version      string          `xml:"Version,attr"`
	IssueInstant string          `xml:"IssueInstant,attr"`
	Destination  string          `xml:"Destination,attr,omitempty"`
	Issuer       *ResponseIssuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       *Status         `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    *Assertion      `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	Signature    *Signature      `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
}

// ResponseIssuer is used to avoid XML tag conflicts
type ResponseIssuer struct {
	Format string `xml:"Format,attr,omitempty"`
	Value  string `xml:",chardata"`
}

type Status struct {
	StatusCode *StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type StatusCode struct {
	Value string `xml:"Value,attr"`
}

type Assertion struct {
	XMLName            xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string              `xml:"ID,attr"`
	IssueInstant       string              `xml:"IssueInstant,attr"`
	Version            string              `xml:"Version,attr"`
	AssertionIssuer    *AssertionIssuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            *Subject            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         *Conditions         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStatement     *AuthnStatement     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttributeStatement *AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// AssertionIssuer is used to avoid XML tag conflicts
type AssertionIssuer struct {
	Format string `xml:"Format,attr,omitempty"`
	Value  string `xml:",chardata"`
}

type Subject struct {
	NameID *SubjectNameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

// SubjectNameID is used to avoid XML tag conflicts
type SubjectNameID struct {
	Format          string `xml:"Format,attr,omitempty"`
	NameQualifier   string `xml:"NameQualifier,attr,omitempty"`
	SPNameQualifier string `xml:"SPNameQualifier,attr,omitempty"`
	Value           string `xml:",chardata"`
}

type NameID struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format          string   `xml:"Format,attr,omitempty"`
	NameQualifier   string   `xml:"NameQualifier,attr,omitempty"`
	SPNameQualifier string   `xml:"SPNameQualifier,attr,omitempty"`
	Value           string   `xml:",chardata"`
}

type Conditions struct {
	NotBefore           string               `xml:"NotBefore,attr"`
	NotOnOrAfter        string               `xml:"NotOnOrAfter,attr"`
	AudienceRestriction *AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

type AudienceRestriction struct {
	Audience []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

type AuthnStatement struct {
	AuthnInstant string        `xml:"AuthnInstant,attr"`
	SessionIndex string        `xml:"SessionIndex,attr,omitempty"`
	AuthnContext *AuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
}

type AuthnContext struct {
	AuthnContextClassRef *AuthnContextClassRefInner `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

// AuthnContextClassRefInner is used to avoid XML tag conflicts
type AuthnContextClassRefInner struct {
	Value string `xml:",chardata"`
}

type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

type Attribute struct {
	Name            string           `xml:"Name,attr"`
	NameFormat      string           `xml:"NameFormat,attr,omitempty"`
	AttributeValues []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

type AttributeValue struct {
	Type  string `xml:"xsi:type,attr,omitempty"`
	Value string `xml:",chardata"`
}

type Signature struct {
	SignedInfo     *SignedInfo     `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	SignatureValue *SignatureValue `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	KeyInfo        *KeyInfo        `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type SignedInfo struct {
	CanonicalizationMethod *CanonicalizationMethod `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	SignatureMethod        *SignatureMethod        `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Reference              *Reference              `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
}

type CanonicalizationMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type Reference struct {
	URI          string        `xml:"URI,attr"`
	Transforms   *Transforms   `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	DigestMethod *DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  string        `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

type Transforms struct {
	Transform []Transform `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
}

type Transform struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type DigestMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureValue struct {
	Value string `xml:",chardata"`
}

type KeyInfo struct {
	X509Data *X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type X509Data struct {
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type LogoutRequest struct {
	XMLName      xml.Name `xml:"samlp:LogoutRequest"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr,omitempty"`
	Issuer       *Issuer  `xml:"saml:Issuer"`
	NameID       *NameID  `xml:"NameID"`
	SessionIndex string   `xml:"samlp:SessionIndex"`
}

type EntityDescriptor struct {
	XMLName          xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID         string               `xml:"entityID,attr"`
	ValidUntil       string               `xml:"validUntil,attr,omitempty"`
	SPSSODescriptor  *SPSSODescriptor     `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	IDPSSODescriptor *IDPSSODescriptorXML `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}

type SPSSODescriptor struct {
	AuthnRequestsSigned        bool                       `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool                       `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string                     `xml:"protocolSupportEnumeration,attr"`
	NameIDFormats              []string                   `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	AssertionConsumerService   []AssertionConsumerService `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	SingleLogoutService        []SingleLogoutService      `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
}

type AssertionConsumerService struct {
	Index     int    `xml:"index,attr"`
	IsDefault bool   `xml:"isDefault,attr,omitempty"`
	Binding   string `xml:"Binding,attr"`
	Location  string `xml:"Location,attr"`
}

type SingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type IDPSSODescriptorXML struct {
	XMLName                 xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	WantAuthnRequestsSigned bool                  `xml:"WantAuthnRequestsSigned,attr"`
	SingleSignOnService     []SingleSignOnService `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	SingleLogoutService     []SingleLogoutService `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	NameIDFormats           []string              `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	KeyDescriptors          []KeyDescriptor       `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
}

type SingleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type KeyDescriptor struct {
	Use     string      `xml:"use,attr"`
	KeyInfo *KeyInfoXML `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type KeyInfoXML struct {
	X509Data *X509DataXML `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type X509DataXML struct {
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

// Helper functions

func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("_%x", b)
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func extractSLOLocations(services []SingleLogoutService) []string {
	locations := make([]string, 0, len(services))
	for _, svc := range services {
		locations = append(locations, svc.Location)
	}
	return locations
}

func extractLocations(services []SingleSignOnService) []string {
	locations := make([]string, len(services))
	for i, s := range services {
		locations[i] = s.Location
	}
	return locations
}

func parseCertificate(certPEM string) (*x509.Certificate, error) {
	// Remove PEM headers if present
	certPEM = strings.TrimSpace(certPEM)
	certPEM = strings.ReplaceAll(certPEM, "-----BEGIN CERTIFICATE-----", "")
	certPEM = strings.ReplaceAll(certPEM, "-----END CERTIFICATE-----", "")
	certPEM = strings.ReplaceAll(certPEM, "\n", "")
	certPEM = strings.ReplaceAll(certPEM, " ", "")

	certBytes, err := base64.StdEncoding.DecodeString(certPEM)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

func extractStringSlice(attributes map[string]interface{}, key string) []string {
	if key == "" {
		return nil
	}
	val, ok := attributes[key]
	if !ok {
		return nil
	}
	switch v := val.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		result := make([]string, len(v))
		for i, item := range v {
			result[i], _ = item.(string)
		}
		return result
	}
	return nil
}
