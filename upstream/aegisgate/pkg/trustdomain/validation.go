// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package trustdomain

import (
	"time"
)

// ValidateCertificate validates a certificate using the trust domain
func (ve *ValidationEngine) ValidateCertificate(cert interface{}) (*AttestationResult, error) {
	ve.mu.Lock()
	ve.stats.TotalValidations++
	ve.mu.Unlock()

	result, err := ve.domain.ValidateCertificate(cert)

	ve.mu.Lock()
	if err == nil && result != nil {
		ve.stats.Successful++
	} else {
		ve.stats.Failed++
		ve.stats.LastError = err.Error()
	}
	ve.stats.LastValidationTime = time.Now()
	ve.mu.Unlock()

	return result, err
}

// ValidateSignature validates a signature using the trust domain
func (ve *ValidationEngine) ValidateSignature(data, signature []byte) (bool, error) {
	ve.mu.Lock()
	ve.stats.TotalValidations++
	ve.mu.Unlock()

	valid, err := ve.domain.ValidateSignature(data, signature)

	ve.mu.Lock()
	if err == nil && valid {
		ve.stats.Successful++
	} else {
		ve.stats.Failed++
		ve.stats.LastError = err.Error()
	}
	ve.stats.LastValidationTime = time.Now()
	ve.mu.Unlock()

	return valid, err
}

// ValidateHashChain validates a hash chain
func (ve *ValidationEngine) ValidateHashChain(hash, previousHash string) (bool, error) {
	ve.mu.Lock()
	ve.stats.TotalValidations++
	ve.mu.Unlock()

	valid, err := ve.domain.ValidateHashChain(hash, previousHash)

	ve.mu.Lock()
	if err == nil && valid {
		ve.stats.Successful++
	} else {
		ve.stats.Failed++
		ve.stats.LastError = err.Error()
	}
	ve.stats.LastValidationTime = time.Now()
	ve.mu.Unlock()

	return valid, err
}

// GetStats returns validation statistics
func (ve *ValidationEngine) GetStats() *ValidationStats {
	ve.mu.RLock()
	defer ve.mu.RUnlock()
	return ve.stats
}
