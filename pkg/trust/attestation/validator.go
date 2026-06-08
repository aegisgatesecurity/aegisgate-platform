package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// Validator verifies compliance attestations
type Validator struct{}

// NewValidator creates a new attestation validator
func NewValidator() *Validator {
	return &Validator{}
}

// Verify verifies an attestation's signature and validity
func (v *Validator) Verify(att *Attestation) (*AttestationResult, error) {
	result := &AttestationResult{
		AgentID:    att.AgentID,
		Frameworks: att.Frameworks,
		IssuedAt:   att.IssuedAt,
		ExpiresAt:  att.ExpiresAt,
		VerifiedAt: time.Now().UTC(),
	}

	// Check expiration
	if time.Now().After(att.ExpiresAt) {
		result.Valid = false
		result.Errors = append(result.Errors, "attestation has expired")
		return result, nil
	}

	// Verify signature
	if err := v.verifySignature(att); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("signature verification failed: %v", err))
		return result, nil
	}

	// Count statement results
	for _, stmt := range att.Statements {
		if stmt.Passed {
			result.StatementsPass++
		} else {
			result.StatementsFail++
		}
	}

	// Attestation is valid if signature checks out
	result.Valid = true
	return result, nil
}

func (v *Validator) verifySignature(att *Attestation) error {
	if len(att.SignerPublicKey) == 0 || len(att.Signature) == 0 {
		return fmt.Errorf("missing signature or public key")
	}

	// Unmarshal public key
	//nolint:staticcheck // SA1019: elliptic.Unmarshal is deprecated as of Go 1.21 in favor of crypto/ecdh.
	// See the corresponding comment in generator.go:64 — migration is planned for v3.4.0+
	// and requires a wider refactor of the trust/attestation package.
	x, y := elliptic.Unmarshal(elliptic.P256(), att.SignerPublicKey)
	if x == nil {
		return fmt.Errorf("invalid public key")
	}
	pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// Reconstruct the signed data
	data, _ := json.Marshal(map[string]interface{}{
		"id":         att.ID,
		"agentId":    att.AgentID,
		"contractId": att.ContractID,
		"frameworks": att.Frameworks,
		"issuedAt":   att.IssuedAt,
		"expiresAt":  att.ExpiresAt,
		"statements": att.Statements,
	})

	hash := sha256.Sum256(data)
	ok := ecdsa.VerifyASN1(pubKey, hash[:], att.Signature)
	if !ok {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// VerifyWithPublicKey verifies using a provided public key
func (v *Validator) VerifyWithPublicKey(att *Attestation, pubKey *ecdsa.PublicKey) (*AttestationResult, error) {
	result := &AttestationResult{
		AgentID:    att.AgentID,
		Frameworks: att.Frameworks,
		IssuedAt:   att.IssuedAt,
		ExpiresAt:  att.ExpiresAt,
		VerifiedAt: time.Now().UTC(),
	}

	if time.Now().After(att.ExpiresAt) {
		result.Valid = false
		result.Errors = append(result.Errors, "attestation has expired")
		return result, nil
	}

	data, _ := json.Marshal(map[string]interface{}{
		"id":         att.ID,
		"agentId":    att.AgentID,
		"contractId": att.ContractID,
		"frameworks": att.Frameworks,
		"issuedAt":   att.IssuedAt,
		"expiresAt":  att.ExpiresAt,
		"statements": att.Statements,
	})

	hash := sha256.Sum256(data)
	ok := ecdsa.VerifyASN1(pubKey, hash[:], att.Signature)
	if !ok {
		result.Valid = false
		result.Errors = append(result.Errors, "signature verification failed")
		return result, nil
	}

	for _, stmt := range att.Statements {
		if stmt.Passed {
			result.StatementsPass++
		} else {
			result.StatementsFail++
		}
	}

	result.Valid = true
	return result, nil
}

// ValidateStatement checks individual attestation statements
func (v *Validator) ValidateStatement(stmt *Statement) error {
	if stmt.Type == "" {
		return fmt.Errorf("statement type is required")
	}
	if stmt.Description == "" {
		return fmt.Errorf("statement description is required")
	}
	return nil
}

// ParseSignature parses an ASN.1 ECDSA signature
func ParseSignature(sig []byte) (r, s *big.Int, err error) {
	var parsed asn1Signature
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return nil, nil, err
	}
	return parsed.R, parsed.S, nil
}

type asn1Signature struct {
	R, S *big.Int
}
