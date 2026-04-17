// Package signature_verification provides digital signature verification.
package signature_verification

// SignatureValidationService provides high-level signature validation
type SignatureValidationService struct {
	verifier   *SignatureVerifier
	strictMode bool
}

// NewSignatureValidationService creates a new validation service
func NewSignatureValidationService() *SignatureValidationService {
	return &SignatureValidationService{
		verifier:   NewSignatureVerifier(),
		strictMode: true,
	}
}

// ValidateSignature validates a signature
func (s *SignatureValidationService) ValidateSignature(payload []byte, signature []byte, publicKey []byte) (*VerificationResult, error) {
	return s.verifier.VerifySignature(payload, signature, publicKey)
}

// ValidateSignedPackage validates a signed payload
func (s *SignatureValidationService) ValidateSignedPackage(signed *SignedPayload) (*VerificationResult, error) {
	return s.verifier.ValidateSignedPayload(signed)
}

// ValidateStringSignature validates a base64-encoded signature
func (s *SignatureValidationService) ValidateStringSignature(payload []byte, signature string, publicKey []byte) (*VerificationResult, error) {
	return s.verifier.VerifyStringSignature(payload, signature, publicKey)
}

// EnableStrictMode enables strict mode
func (s *SignatureValidationService) EnableStrictMode() {
	s.strictMode = true
	s.verifier.EnableStrictMode()
}

// DisableStrictMode disables strict mode
func (s *SignatureValidationService) DisableStrictMode() {
	s.strictMode = false
	s.verifier.DisableStrictMode()
}

// IsStrictModeEnabled returns whether strict mode is enabled
func (s *SignatureValidationService) IsStrictModeEnabled() bool {
	return s.strictMode
}

// GetVerificationStats returns statistics
func (s *SignatureValidationService) GetVerificationStats() *VerificationStats {
	return s.verifier.GetStats()
}

// KeyManagementService provides key management
type KeyManagementService struct {
	keyManager *KeyManager
}

// NewKeyManagementService creates a new key management service
func NewKeyManagementService(keyStorePath string) *KeyManagementService {
	return &KeyManagementService{
		keyManager: NewKeyManager(keyStorePath),
	}
}

// LoadPublicKey loads a public key
func (s *KeyManagementService) LoadPublicKey(keyID string, pemData []byte, usage []string) error {
	return s.keyManager.LoadPublicKey(keyID, pemData, usage)
}

// RevokeKey revokes a key
func (s *KeyManagementService) RevokeKey(keyID string) error {
	return s.keyManager.RevokeKey(keyID)
}

// GetPublicKeyInfo retrieves public key info
func (s *KeyManagementService) GetPublicKeyInfo(keyID string) (*PublicKeyInfo, error) {
	info, _, err := s.keyManager.GetPublicKey(keyID)
	return info, err
}
