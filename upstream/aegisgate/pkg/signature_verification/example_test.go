package signature_verification

import (
	"fmt"
)

// Example demonstrates how to use the signature verification package
func Example() {
	verifier := NewSignatureVerifier()
	verifier.Enable()

	// Load a public key
	pemData := []byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----\n")

	err := verifier.keyManager.LoadPublicKey("key-1", pemData, []string{"verify"})
	if err != nil {
		fmt.Printf("Error loading public key: %v\n", err)
		return
	}

	// Verify a signature
	payload := []byte("example payload")
	signature := []byte("example signature")

	result, err := verifier.VerifySignature(payload, signature, pemData)
	if err != nil {
		fmt.Printf("Verification error: %v\n", err)
		return
	}

	if result.Valid {
		fmt.Println("Signature is valid")
	} else {
		fmt.Println("Signature is invalid")
	}

	// Get verification statistics
	stats := verifier.GetStats()
	fmt.Printf("Total verifications: %d, Successful: %d, Failed: %d\n",
		stats.TotalVerifications, stats.Successful, stats.Failed)
}
