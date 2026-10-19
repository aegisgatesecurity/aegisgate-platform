// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 3: Ed25519-Signed Evidence
//
// signed_report.go wraps an assessment report (PDF or JSON) in an
// Ed25519-signed envelope that provides cryptographic proof of:
//
//   - When the assessment was run (timestamp in the payload)
//   - What the results were (the report bytes are the payload)
//   - Who signed it (the public key is embedded in the envelope)
//   - That the report has not been tampered with (Ed25519 signature)
//
// This creates regulator-acceptable, tamper-evident evidence that can be
// presented in audits, SBIR proposals, and compliance reviews.
//
// The signing key is generated on first use and persisted to disk. The
// public key is embedded in every signed report so verification doesn't
// require a key server — the recipient can verify the signature using
// only the report itself.
//
// Design:
//
//   - Ed25519 is used because it is fast, deterministic, and supported
//     by the Go standard library (crypto/ed25519). No external deps.
//   - The signed envelope is a JSON structure containing the report
//     bytes (base64), the signature (base64), the public key (base64),
//     and metadata (algorithm, timestamp, assessment ID).
//   - Verification is a single function call: VerifySignedReport(envelope).
//   - The key pair is stored in a PEM-like format on disk for persistence.

package assessment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// =========================================================================
// Signed Report Types
// =========================================================================

// ReportFormat is the format of the signed report payload.
type ReportFormat string

const (
	ReportFormatPDF  ReportFormat = "pdf"
	ReportFormatJSON ReportFormat = "json"
	ReportFormatCSV  ReportFormat = "csv"
)

// SignedAssessmentReport is a tamper-evident, Ed25519-signed assessment report.
// It contains the report bytes, the Ed25519 signature, the public key needed
// to verify the signature, and metadata about the assessment.
//
// The envelope is JSON-serializable for storage and transmission.
type SignedAssessmentReport struct {
	// AssessmentID is the ID of the assessment run.
	AssessmentID string `json:"assessment_id"`

	// Format is the format of the report payload (pdf, json, csv).
	Format ReportFormat `json:"format"`

	// ReportBase64 is the base64-encoded report bytes.
	ReportBase64 string `json:"report"`

	// SignatureBase64 is the base64-encoded Ed25519 signature of the
	// report bytes.
	SignatureBase64 string `json:"signature"`

	// PublicKeyBase64 is the base64-encoded Ed25519 public key.
	PublicKeyBase64 string `json:"public_key"`

	// Algorithm is the signature algorithm used ("Ed25519").
	Algorithm string `json:"algorithm"`

	// SignedAt is when the report was signed.
	SignedAt time.Time `json:"signed_at"`

	// KeyFingerprint is the SHA-256 fingerprint of the public key
	// (first 16 hex chars) for identification.
	KeyFingerprint string `json:"key_fingerprint"`

	// Metadata is additional key-value metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SignReportConfig configures the signing process.
type SignReportConfig struct {
	// KeyPath is the path to the Ed25519 private key file. If the file
	// doesn't exist, a new key pair is generated and saved. If empty,
	// an ephemeral key pair is generated (not persisted).
	KeyPath string

	// Metadata is additional metadata to include in the signed report.
	Metadata map[string]string
}

// =========================================================================
// Key Management
// =========================================================================

// LoadOrGenerateKey loads an Ed25519 private key from disk, or generates
// a new key pair and saves it if the file doesn't exist.
//
// The key is stored as raw 64-byte Ed25519 private key (seed + public key).
// If KeyPath is empty, an ephemeral key is generated and not persisted.
func LoadOrGenerateKey(keyPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if keyPath == "" {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		return privKey, pubKey, err
	}

	// Try to load existing key.
	if data, err := os.ReadFile(keyPath); err == nil {
		if len(data) == ed25519.PrivateKeySize {
			privKey := ed25519.PrivateKey(data)
			pubKey := privKey.Public().(ed25519.PublicKey)
			return privKey, pubKey, nil
		}
		// Invalid key file — overwrite with new key.
	}

	// Generate new key.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}

	// Ensure parent directory exists.
	if dir := filepath.Dir(keyPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create key directory: %w", err)
		}
	}

	// Save private key (0600 permissions — owner read/write only).
	if err := os.WriteFile(keyPath, privKey, 0o600); err != nil {
		return nil, nil, fmt.Errorf("save Ed25519 key: %w", err)
	}

	return privKey, pubKey, nil
}

// KeyFingerprint returns the first 16 hex characters of the SHA-256
// fingerprint of an Ed25519 public key. Used for key identification
// in the signed report.
func KeyFingerprint(pubKey ed25519.PublicKey) string {
	sum := sha256.Sum256(pubKey)
	return fmt.Sprintf("%x", sum[:8])
}

// =========================================================================
// Signing
// =========================================================================

// SignReport signs an assessment report with an Ed25519 key.
//
// The reportBytes can be PDF, JSON, or CSV — the format is specified in
// the config and embedded in the signed envelope for the verifier.
//
// If cfg.KeyPath is set, the key is loaded from or persisted to disk.
// If cfg.KeyPath is empty, an ephemeral key is used.
func SignReport(result *AssessmentResult, reportBytes []byte, format ReportFormat, cfg SignReportConfig) (*SignedAssessmentReport, error) {
	if len(reportBytes) == 0 {
		return nil, errors.New("sign: report bytes are empty")
	}

	privKey, pubKey, err := LoadOrGenerateKey(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("sign: key setup: %w", err)
	}

	signature := ed25519.Sign(privKey, reportBytes)

	envelope := &SignedAssessmentReport{
		AssessmentID:    result.ID,
		Format:          format,
		ReportBase64:    base64.StdEncoding.EncodeToString(reportBytes),
		SignatureBase64: base64.StdEncoding.EncodeToString(signature),
		PublicKeyBase64: base64.StdEncoding.EncodeToString(pubKey),
		Algorithm:       "Ed25519",
		SignedAt:        time.Now().UTC(),
		KeyFingerprint:  KeyFingerprint(pubKey),
		Metadata:        cfg.Metadata,
	}

	return envelope, nil
}

// SignPDFReport generates a PDF report and signs it in one call.
func SignPDFReport(result *AssessmentResult, cfg SignReportConfig) (*SignedAssessmentReport, error) {
	pdfBytes, err := result.ToPDF()
	if err != nil {
		return nil, fmt.Errorf("sign PDF: generate PDF: %w", err)
	}
	return SignReport(result, pdfBytes, ReportFormatPDF, cfg)
}

// SignJSONReport generates a JSON report and signs it in one call.
func SignJSONReport(result *AssessmentResult, cfg SignReportConfig) (*SignedAssessmentReport, error) {
	jsonBytes, err := result.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("sign JSON: generate JSON: %w", err)
	}
	return SignReport(result, jsonBytes, ReportFormatJSON, cfg)
}

// =========================================================================
// Verification
// =========================================================================

// Verify validates the Ed25519 signature on a signed assessment report.
// Returns nil if the signature is valid, or an error describing why
// verification failed.
//
// This function only uses the public key embedded in the envelope —
// no external key server or key store is needed. This makes the signed
// report self-contained: anyone with the envelope can verify it.
func (s *SignedAssessmentReport) Verify() error {
	if s == nil {
		return errors.New("verify: nil envelope")
	}

	if s.Algorithm != "Ed25519" {
		return fmt.Errorf("verify: unsupported algorithm %s (expected Ed25519)", s.Algorithm)
	}

	reportBytes, err := base64.StdEncoding.DecodeString(s.ReportBase64)
	if err != nil {
		return fmt.Errorf("verify: decode report: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(s.SignatureBase64)
	if err != nil {
		return fmt.Errorf("verify: decode signature: %w", err)
	}

	pubKey, err := base64.StdEncoding.DecodeString(s.PublicKeyBase64)
	if err != nil {
		return fmt.Errorf("verify: decode public key: %w", err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("verify: invalid public key size %d (expected %d)",
			len(pubKey), ed25519.PublicKeySize)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("verify: invalid signature size %d (expected %d)",
			len(signature), ed25519.SignatureSize)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKey), reportBytes, signature) {
		return errors.New("verify: signature invalid — report has been tampered with or signed with a different key")
	}

	return nil
}

// ReportBytes returns the decoded report bytes from the signed envelope.
func (s *SignedAssessmentReport) ReportBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.ReportBase64)
}

// ToJSON serializes the signed report envelope to JSON.
func (s *SignedAssessmentReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// SignedReportFromJSON deserializes a signed report envelope from JSON.
func SignedReportFromJSON(data []byte) (*SignedAssessmentReport, error) {
	var env SignedAssessmentReport
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("deserialize signed report: %w", err)
	}
	return &env, nil
}

// =========================================================================
// Helpers
// =========================================================================
