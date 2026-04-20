// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// IntegrityChecker verifies configuration integrity
type IntegrityChecker struct {
	Hash string
}

// NewIntegrityChecker creates a new integrity checker
func NewIntegrityChecker() *IntegrityChecker {
	return &IntegrityChecker{}
}

// ComputeHash computes the SHA256 hash of the configuration data
func (ic *IntegrityChecker) ComputeHash(version string, data map[string]interface{}, metadata map[string]string) (string, error) {
	input := fmt.Sprintf("%s%v%v", version, data, metadata)
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:]), nil
}

// Verify verifies that the stored hash matches the computed hash
func (ic *IntegrityChecker) Verify(storedHash string, version string, data map[string]interface{}, metadata map[string]string) (bool, error) {
	computedHash, err := ic.ComputeHash(version, data, metadata)
	if err != nil {
		return false, err
	}
	return storedHash == computedHash, nil
}

// IntegrityError represents an integrity verification failure
type IntegrityError struct {
	Message string
	Hash    string
	Stored  string
}

// Error implements the error interface
func (e *IntegrityError) Error() string {
	return e.Message
}

// NewIntegrityError creates a new integrity error
func NewIntegrityError(message string, hash string, stored string) *IntegrityError {
	return &IntegrityError{
		Message: message,
		Hash:    hash,
		Stored:  stored,
	}
}
