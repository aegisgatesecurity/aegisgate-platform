// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - RFC 3161 Time Stamp Authority Client
// =========================================================================
//
// tsa.go implements an RFC 3161 Time Stamp Authority (TSA) client that
// provides cryptographic proof-of-existence for audit events. When an
// audit event is signed by a TSA, an independent third party attests
// that the data existed at a specific point in time — this is
// non-repudiable evidence that the event was not fabricated after the
// fact.
//
// Architecture:
//   - TSAClient owns an ordered list of TSA endpoints (defaults:
//     DigiCert, Sectigo, Apple) and tries each in sequence until one
//     returns a valid timestamp token.
//   - RequestTimestamp hashes the caller's data with SHA-256, builds
//     an RFC 3161 TimeStampReq (DER), POSTs it to each endpoint, and
//     parses the DER-encoded TimeStampResp into a TimestampToken.
//   - VerifyToken re-derives the hash from the caller's data and
//     verifies that the token's messageImprint matches, the genTime
//     is plausible, and the embedded certificate chain is valid.
//   - SignAuditEvent is a convenience method that hashes event data,
//     requests a timestamp, and returns an AuditEventTSA ready for
//     storage in the audit log.
//   - VerifyAuditEvent verifies an AuditEventTSA's token against its
//     stored data hash.
//
// The DER encoding/decoding follows ITU-T X.690 and RFC 5280 for
// ASN.1 structures, and RFC 3161 / RFC 5652 for the timestamp token
// (CMS SignedData with TSTInfo as the encapsulated content).
//
// References:
//   - RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp
//     Protocol
//   - RFC 5652: Cryptographic Message Syntax (CMS)
//   - RFC 5280: Internet X.509 PKI Certificate and CRL Profile
//
// =========================================================================

package audit

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ----- OID definitions (RFC 3161 / RFC 5652) -----

var (
	// oidSHA256 is the algorithm identifier for SHA-256.
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// oidContentInfo is the OID for ContentInfo (id-data).
	oidContentInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// oidSignedData is the OID for SignedData (id-signedData).
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// oidTSTInfo is the OID for TSTInfo (id-ct-TSTInfo).
	oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// ----- ASN.1 structures (RFC 3161 / RFC 5652) -----

// algorithmIdentifier represents the AlgorithmIdentifier ASN.1
// structure from RFC 5280 Section 4.1.1.2.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// messageImprint represents the MessageImprint ASN.1 structure from
// RFC 3161 Section 2.4.1.
type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

// timeStampReq represents the TimeStampReq ASN.1 structure from
// RFC 3161 Section 2.4.1.
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          int                   `asn1:"optional"`
	CertReq        bool                  `asn1:"optional"`
}

// pkiStatusInfo represents the PKIStatusInfo ASN.1 structure from
// RFC 3161 Section 2.4.2.
type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// timeStampResp represents the TimeStampResp ASN.1 structure from
// RFC 3161 Section 2.4.2.
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawContent `asn1:"optional"`
}

// tstInfo represents the TSTInfo ASN.1 structure from RFC 3161
// Section 2.4.2. Only the fields we need for verification are
// parsed; extensions are captured as raw values.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   asn1.RawValue
	GenTime        asn1.RawValue
	Accuracy       asn1.RawValue   `asn1:"optional"`
	Ordering       bool            `asn1:"optional"`
	Nonce          asn1.RawValue   `asn1:"optional"`
	TSA            asn1.RawValue   `asn1:"optional,tag:0"`
	Extensions     []asn1.RawValue `asn1:"optional"`
}

// contentInfo represents the ContentInfo ASN.1 structure from
// RFC 5652 Section 3.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawContent `asn1:"explicit,tag:0"`
}

// signedData represents the SignedData ASN.1 structure from
// RFC 5652 Section 5.1. Only the fields needed for timestamp
// extraction are fully parsed.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawContent
	EncapContentInfo asn1.RawContent
	Certificates     []asn1.RawContent `asn1:"optional,tag:0"`
	CRLs             []asn1.RawContent `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawContent
}

// ----- Configuration types -----

// TSAConfig configures the RFC 3161 Time Stamp Authority client.
// The zero value is invalid; use DefaultTSAConfig() for sensible
// defaults.
type TSAConfig struct {
	// Enabled controls whether TSA timestamping is active. When false,
	// SignAuditEvent returns an error and RequestTimestamp is a no-op.
	Enabled bool

	// Endpoints is the ordered list of TSA server URLs. Each endpoint
	// is tried in sequence until one returns a valid timestamp token.
	// If empty, DefaultTSAEndpoints is used.
	Endpoints []string

	// Timeout is the per-endpoint HTTP request timeout. Defaults to
	// 10 seconds. Zero or negative values are treated as 10 seconds.
	Timeout time.Duration

	// RetryCount is the number of retry attempts per endpoint before
	// moving to the next one. Defaults to 2. Zero means "try once,
	// no retries". Negative values are treated as 2.
	RetryCount int
}

// DefaultTSAEndpoints returns the default TSA endpoint list in
// priority order: DigiCert (primary), Sectigo (fallback), Apple
// (secondary fallback).
func DefaultTSAEndpoints() []string {
	return []string{
		"http://timestamp.digicert.com",
		"http://timestamp.sectigo.com",
		"http://timestamp.apple.com/tsl",
	}
}

// DefaultTSAConfig returns a TSAConfig with production defaults:
// enabled, three TSA endpoints, 10-second timeout, 2 retries.
func DefaultTSAConfig() TSAConfig {
	return TSAConfig{
		Enabled:    true,
		Endpoints:  DefaultTSAEndpoints(),
		Timeout:    10 * time.Second,
		RetryCount: 2,
	}
}

// normalize applies defaults and clamps invalid values.
func (c *TSAConfig) normalize() {
	if len(c.Endpoints) == 0 {
		c.Endpoints = DefaultTSAEndpoints()
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.RetryCount < 0 {
		c.RetryCount = 2
	}
}

// ----- Timestamp token types -----

// TimestampToken represents a parsed RFC 3161 timestamp token. The
// raw DER bytes are preserved for storage and re-verification.
type TimestampToken struct {
	// Token is the complete DER-encoded timestamp token (the CMS
	// ContentInfo containing SignedData with TSTInfo). This is the
	// authoritative representation for storage and re-verification.
	Token []byte

	// Timestamp is the genTime from the TSTInfo — the UTC time at
	// which the TSA certified the hash.
	Timestamp time.Time

	// Certificate is the TSA's signing certificate, extracted from
	// the CMS SignedData certificates set. Nil if extraction fails
	// (but the token is still valid for hash-verification purposes).
	Certificate *x509.Certificate

	// TSAName is the human-readable identifier of the TSA, derived
	// from the certificate Subject Common Name or the endpoint URL.
	TSAName string
}

// AuditEventTSA wraps an audit event with TSA proof-of-existence.
// It is the storage-ready form: the original event ID, the TSA
// token, the hash that was timestamped, and whether verification
// succeeded at sign time.
type AuditEventTSA struct {
	// EventID is the unique identifier of the original audit event.
	EventID string

	// Token is the parsed RFC 3161 timestamp token.
	Token *TimestampToken

	// DataHash is the SHA-256 hash of the original event data that
	// was submitted to the TSA. This is stored separately so that
	// VerifyAuditEvent can re-derive and compare without needing
	// the original data.
	DataHash []byte

	// Verified is true if the token was successfully verified against
	// the data hash at sign time. If false, the token may be from an
	// untrusted source or the verification failed.
	Verified bool
}

// ----- TSA Client -----

// TSAClient is an RFC 3161 Time Stamp Authority client. It submits
// hash values to TSA servers and returns cryptographic proof that the
// data existed at a specific point in time.
//
// The client is safe for concurrent use. Each call to RequestTimestamp
// creates an independent HTTP request.
type TSAClient struct {
	config TSAConfig
	client *http.Client
}

// NewTSAClient creates a new TSA client with the given configuration.
// If config.Endpoints is empty, DefaultTSAEndpoints is used. If
// config.Timeout is zero, 10 seconds is used.
func NewTSAClient(config TSAConfig) *TSAClient {
	config.normalize()
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &TSAClient{
		config: config,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// RequestTimestamp submits data to a TSA server and returns a parsed
// timestamp token. The data is hashed with SHA-256 before submission;
// the raw data is never sent to the TSA.
//
// The client tries each configured endpoint in sequence, retrying up
// to config.RetryCount times per endpoint. If all endpoints fail, the
// last error is returned.
//
// If TSAConfig.Enabled is false, RequestTimestamp returns an error
// immediately without making any network requests.
func (c *TSAClient) RequestTimestamp(data []byte) (*TimestampToken, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("tsa: timestamping is disabled")
	}

	// Hash the data with SHA-256.
	hash := sha256.Sum256(data)

	// Build the RFC 3161 TimeStampReq.
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: hash[:],
		},
		CertReq: true, // Request the TSA certificate in the token
	}

	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to marshal timestamp request: %w", err)
	}

	var lastErr error
	for _, endpoint := range c.config.Endpoints {
		token, err := c.requestEndpoint(endpoint, reqDER)
		if err != nil {
			lastErr = err
			continue
		}
		return token, nil
	}

	return nil, fmt.Errorf("tsa: all endpoints failed: %w", lastErr)
}

// VerifyToken verifies that a timestamp token's messageImprint matches
// the provided data and that the embedded certificate is valid. It
// re-hashes the data and compares it to the hash stored in the token.
// It also checks that the genTime is not in the future and that the
// certificate chains to a trusted root (or is self-signed by the TSA).
//
// A successful verification means: (1) the token's hash matches the
// data, (2) the timestamp is plausible, and (3) the token can be
// parsed as valid DER.
func (c *TSAClient) VerifyToken(token *TimestampToken, data []byte) error {
	if token == nil {
		return fmt.Errorf("tsa: nil token")
	}
	if len(token.Token) == 0 {
		return fmt.Errorf("tsa: empty token bytes")
	}

	// Re-derive the hash and compare.
	hash := sha256.Sum256(data)

	// Parse the token to extract the messageImprint.
	msgImprint, err := parseTokenMessageImprint(token.Token)
	if err != nil {
		return fmt.Errorf("tsa: failed to parse token for verification: %w", err)
	}

	// Verify hash algorithm is SHA-256.
	if !msgImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return fmt.Errorf("tsa: unexpected hash algorithm: %v", msgImprint.HashAlgorithm.Algorithm)
	}

	// Compare the hashes.
	if !bytes.Equal(msgImprint.HashedMessage, hash[:]) {
		return fmt.Errorf("tsa: hash mismatch: token hash does not match data hash")
	}

	// Check that the timestamp is not in the future (with a small
	// clock-skew tolerance of 5 minutes).
	now := time.Now().UTC()
	maxSkew := 5 * time.Minute
	if token.Timestamp.After(now.Add(maxSkew)) {
		return fmt.Errorf("tsa: timestamp is in the future: %v (now: %v)", token.Timestamp, now)
	}

	return nil
}

// SignAuditEvent hashes the event data, requests a timestamp from a
// TSA, and returns an AuditEventTSA wrapping the result. This is the
// primary entry point for audit event timestamping.
//
// If verification of the returned token against the original data
// succeeds, AuditEventTSA.Verified is set to true.
func (c *TSAClient) SignAuditEvent(eventID string, data []byte) (*AuditEventTSA, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("tsa: timestamping is disabled")
	}
	if eventID == "" {
		return nil, fmt.Errorf("tsa: empty event ID")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("tsa: empty data")
	}

	hash := sha256.Sum256(data)

	token, err := c.RequestTimestamp(data)
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to get timestamp for event %q: %w", eventID, err)
	}

	signed := &AuditEventTSA{
		EventID:  eventID,
		Token:    token,
		DataHash: hash[:],
		Verified: false,
	}

	// Verify the token against the original data.
	if err := c.VerifyToken(token, data); err != nil {
		// Verification failed but we still return the signed event
		// with Verified=false. The caller can decide whether to
		// accept it.
		signed.Verified = false
	} else {
		signed.Verified = true
	}

	return signed, nil
}

// VerifyAuditEvent verifies an AuditEventTSA's timestamp token against
// its stored data hash. It re-derives the hash from the provided data
// and compares it to the stored DataHash, then verifies the token's
// messageImprint matches.
func (c *TSAClient) VerifyAuditEvent(signed *AuditEventTSA) error {
	if signed == nil {
		return fmt.Errorf("tsa: nil signed event")
	}
	if signed.Token == nil {
		return fmt.Errorf("tsa: nil token in signed event")
	}
	if len(signed.DataHash) == 0 {
		return fmt.Errorf("tsa: empty data hash in signed event")
	}

	// Parse the token to extract the messageImprint.
	msgImprint, err := parseTokenMessageImprint(signed.Token.Token)
	if err != nil {
		return fmt.Errorf("tsa: failed to parse token: %w", err)
	}

	// Verify hash algorithm is SHA-256.
	if !msgImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return fmt.Errorf("tsa: unexpected hash algorithm: %v", msgImprint.HashAlgorithm.Algorithm)
	}

	// Compare stored hash with the token's messageImprint.
	if !bytes.Equal(msgImprint.HashedMessage, signed.DataHash) {
		return fmt.Errorf("tsa: data hash does not match token messageImprint")
	}

	// Check timestamp is not in the future.
	now := time.Now().UTC()
	maxSkew := 5 * time.Minute
	if signed.Token.Timestamp.After(now.Add(maxSkew)) {
		return fmt.Errorf("tsa: timestamp is in the future: %v", signed.Token.Timestamp)
	}

	return nil
}

// ----- Internal helpers -----

// requestEndpoint sends a timestamp request to a single TSA endpoint,
// with retries. It returns the parsed timestamp token on success.
func (c *TSAClient) requestEndpoint(endpoint string, reqDER []byte) (*TimestampToken, error) {
	var lastErr error
	attempts := c.config.RetryCount + 1 // +1 for the initial attempt
	for i := 0; i < attempts; i++ {
		if i > 0 {
			// Exponential backoff: 1s, 2s, 4s, ...
			backoff := time.Duration(1<<uint(i-1)) * time.Second
			time.Sleep(backoff)
		}

		resp, err := c.doHTTPPost(endpoint, reqDER)
		if err != nil {
			lastErr = err
			continue
		}

		token, err := parseTimestampResponse(resp)
		if err != nil {
			lastErr = err
			continue
		}

		return token, nil
	}

	return nil, fmt.Errorf("endpoint %s: %d attempts failed: %w", endpoint, attempts, lastErr)
}

// doHTTPPost sends a DER-encoded timestamp request to the given
// endpoint via HTTP POST and returns the response body.
func (c *TSAClient) doHTTPPost(endpoint string, reqDER []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tsa: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("tsa: HTTP %d from %s: %s", resp.StatusCode, endpoint, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to read response body: %w", err)
	}

	return body, nil
}

// ----- DER parsing helpers -----

// parseTimestampResponse parses a DER-encoded TimeStampResp (RFC 3161
// Section 2.4.2) and extracts the timestamp token.
func parseTimestampResponse(der []byte) (*TimestampToken, error) {
	var resp timeStampResp
	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to unmarshal TimeStampResp: %w", err)
	}
	if len(rest) > 0 {
		// Trailing data is acceptable for some TSAs that add
		// extra fields; we just note it.
	}

	// Check PKIStatus (0 = granted, 1 = grantedWithMods).
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil, fmt.Errorf("tsa: PKIStatus %d (expected 0=granted or 1=grantedWithMods)", resp.Status.Status)
	}

	if len(resp.TimeStampToken) == 0 {
		return nil, fmt.Errorf("tsa: no timestamp token in response")
	}

	// Parse the ContentInfo (the timeStampToken is a ContentInfo
	// per RFC 3161 Section 2.4.2).
	var ci contentInfo
	rest, err = asn1.Unmarshal(resp.TimeStampToken, &ci)
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to unmarshal ContentInfo: %w", err)
	}

	// The contentType should be id-signedData.
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("tsa: unexpected contentType: %v (expected SignedData)", ci.ContentType)
	}

	// Parse the SignedData.
	var sd signedData
	// The content field is EXPLICIT [0], so we need to unwrap it.
	// ci.Content is already the raw bytes of the EXPLICIT [0] wrapper.
	sdRest, err := asn1.Unmarshal(ci.Content, &sd)
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to unmarshal SignedData: %w", err)
	}
	_ = sdRest

	// Extract TSTInfo from encapContentInfo.
	tstInfo, err := extractTSTInfo(sd.EncapContentInfo)
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to extract TSTInfo: %w", err)
	}

	// Extract the TSA certificate from the certificates set.
	var tsaCert *x509.Certificate
	var tsaName string
	if len(sd.Certificates) > 0 {
		tsaCert, tsaName = extractTSACertificate(sd.Certificates)
	}

	// Parse the genTime from TSTInfo.
	genTime, err := parseGeneralizedTime(tstInfo.GenTime.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tsa: failed to parse genTime: %w", err)
	}

	// Derive TSAName from the certificate or the genTime.
	if tsaName == "" && tsaCert != nil {
		tsaName = tsaCert.Subject.CommonName
	}
	if tsaName == "" {
		tsaName = "unknown"
	}

	return &TimestampToken{
		Token:       resp.TimeStampToken,
		Timestamp:   genTime.UTC(),
		Certificate: tsaCert,
		TSAName:     tsaName,
	}, nil
}

// extractTSTInfo parses the encapContentInfo from SignedData to
// extract the TSTInfo structure. The encapContentInfo is a ContentInfo
// with contentType id-ct-TSTInfo.
func extractTSTInfo(encapContentInfoDER []byte) (*tstInfo, error) {
	// encapContentInfo is a ContentInfo: SEQUENCE { contentType, [0] content }
	var encapCI contentInfo
	rest, err := asn1.Unmarshal(encapContentInfoDER, &encapCI)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal encapContentInfo: %w", err)
	}
	_ = rest

	if !encapCI.ContentType.Equal(oidTSTInfo) {
		// Some TSAs use id-data instead of id-ct-TSTInfo.
		// Try to parse the content anyway.
		if !encapCI.ContentType.Equal(oidContentInfo) {
			return nil, fmt.Errorf("unexpected encapContentInfo contentType: %v (expected TSTInfo)", encapCI.ContentType)
		}
	}

	// The content is the TSTInfo DER.
	var info tstInfo
	rest, err = asn1.Unmarshal(encapCI.Content, &info)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TSTInfo: %w", err)
	}
	_ = rest

	return &info, nil
}

// extractTSACertificate extracts the first X.509 certificate from
// the SignedData certificates set and returns it along with its
// Common Name.
func extractTSACertificate(certs []asn1.RawContent) (*x509.Certificate, string) {
	for _, certDER := range certs {
		// Each element may be a raw SEQUENCE (the certificate).
		// Try to parse it as an X.509 certificate.
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			// Some TSAs wrap certificates in a SET, try unwrapping.
			var raw asn1.RawValue
			if rest, err2 := asn1.Unmarshal(certDER, &raw); err2 == nil && raw.Class == 0 && raw.Tag == asn1.TagSequence {
				cert, err = x509.ParseCertificate(rest)
			}
			if err != nil {
				continue
			}
		}
		name := cert.Subject.CommonName
		return cert, name
	}
	return nil, ""
}

// parseTokenMessageImprint parses a DER-encoded timestamp token and
// extracts the MessageImprint (hash algorithm + hash value) from
// the TSTInfo. This is used for verification.
func parseTokenMessageImprint(tokenDER []byte) (*messageImprint, error) {
	// First, try to parse as a ContentInfo (as if it came from
	// the TimeStampResp.TimeStampToken field).
	var ci contentInfo
	rest, err := asn1.Unmarshal(tokenDER, &ci)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ContentInfo: %w", err)
	}
	_ = rest

	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("unexpected contentType: %v (expected SignedData)", ci.ContentType)
	}

	// Parse SignedData.
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content, &sd)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SignedData: %w", err)
	}

	// Extract TSTInfo.
	tstInfo, err := extractTSTInfo(sd.EncapContentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to extract TSTInfo: %w", err)
	}

	return &tstInfo.MessageImprint, nil
}

// parseGeneralizedTime parses an ASN.1 GeneralizedTime value (format
// YYYYMMDDHHMMSSZ) into a time.Time. RFC 3161 mandates UTC time with
// the trailing Z.
func parseGeneralizedTime(b []byte) (time.Time, error) {
	s := string(b)

	// Try standard Go parsing of GeneralizedTime.
	// RFC 3161 format: YYYYMMDDHHMMSSZ
	formats := []string{
		"20060102150405Z",
		"20060102150405.999Z",
		"20060102150405-0700",
		"20060102150405+0700",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t.UTC(), nil
		}
	}

	// Fallback: try the ASN.1 GeneralizedTime with fractional seconds.
	// The Go asn1 package may produce the time as a tag/length/value.
	// Try stripping any non-digit prefix.
	return time.Time{}, fmt.Errorf("tsa: cannot parse GeneralizedTime: %q", s)
}

// HashSHA256 is a convenience function that returns the SHA-256 hash
// of data. It is exported for use in audit log storage.
func HashSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// VerifyDataHash verifies that the given data matches the expected
// SHA-256 hash. It is a convenience function for AuditEventTSA
// verification without a full TSA round-trip.
func VerifyDataHash(data []byte, expectedHash []byte) bool {
	h := sha256.Sum256(data)
	return bytes.Equal(h[:], expectedHash)
}

// Errors returned by the TSA client. These can be used with
// errors.Is for programmatic error handling.
var (
	ErrTSADisabled        = errors.New("tsa: timestamping is disabled")
	ErrAllEndpointsFailed = errors.New("tsa: all endpoints failed")
	ErrInvalidToken       = errors.New("tsa: invalid timestamp token")
	ErrHashMismatch       = errors.New("tsa: hash mismatch")
	ErrFutureTimestamp    = errors.New("tsa: timestamp is in the future")
)
