// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v4.5.1+ Phase 4)
// =========================================================================
//
// key_encryption.go implements AES-256-GCM encryption for the
// IOC signing keyring at rest. When a passphrase is provided
// (via AEGISGATE_IOC_KEY_PASSPHRASE), the keyring file is
// encrypted so that a filesystem compromise does not expose
// the ECDSA P-256 private keys.
//
// Design:
//
//   - The passphrase is stretched via SHA-256 to produce a
//    32-byte AES-256 key. This is simple and avoids importing
//    a KDF library; the passphrase is expected to be a long,
//    high-entropy secret (not a human password). A future
//    iteration may use Argon2id or scrypt for human-memorable
//    passphrases.
//
//   - The encrypted file format is:
//
//    {
//      "encrypted": true,
//      "nonce": "<base64 12-byte GCM nonce>",
//      "ciphertext": "<base64 ciphertext+tag>"
//    }
//
//   - The nonce is randomly generated per write (12 bytes,
//    the GCM standard size). The GCM tag (16 bytes) is
//    appended to the ciphertext by crypto/cipher's Seal().
//
//   - When the passphrase is not set, the keyring file is
//    written as plaintext JSON (the existing format). This
//    is backward compatible: existing deployments continue
//    to work without changes.
//
//   - On load, the file is auto-detected: if the JSON has
//    "encrypted": true, the passphrase is required. If no
//    passphrase is set, an error is returned. If the file
//    is plaintext, it is loaded as before.
//
// v4.5.1+ Phase 4: Hardening.
// =========================================================================

package ioc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// encryptedKeyFile is the on-disk format for an encrypted keyring.
type encryptedKeyFile struct {
	Encrypted  bool   `json:"encrypted"`
	Nonce      string `json:"nonce"`      // base64 12-byte GCM nonce
	Ciphertext string `json:"ciphertext"` // base64 ciphertext+tag
}

// deriveKeyFromPassphrase stretches a passphrase to a 32-byte
// AES-256 key via SHA-256. The passphrase should be a long,
// high-entropy secret (32+ characters). For human-memorable
// passphrases, a future iteration will use Argon2id.
func deriveKeyFromPassphrase(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// encryptKeyFile encrypts plaintext data using AES-256-GCM with
// the given passphrase. Returns the encrypted file JSON. The
// nonce is randomly generated.
func encryptKeyFile(plaintext []byte, passphrase string) ([]byte, error) {
	key := deriveKeyFromPassphrase(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	enc := encryptedKeyFile{
		Encrypted:  true,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.MarshalIndent(enc, "", "  ")
}

// decryptKeyFile decrypts an encrypted keyring file using the
// given passphrase. Returns the plaintext data. Returns an
// error if the passphrase is wrong (GCM authentication failure).
func decryptKeyFile(data []byte, passphrase string) ([]byte, error) {
	var enc encryptedKeyFile
	if err := json.Unmarshal(data, &enc); err != nil {
		return nil, fmt.Errorf("unmarshal encrypted file: %w", err)
	}
	if !enc.Encrypted {
		// Not encrypted; return as-is.
		return data, nil
	}
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	key := deriveKeyFromPassphrase(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt (wrong passphrase?): %w", err)
	}
	return plaintext, nil
}

// isEncryptedKeyFile returns true if the data looks like an
// encrypted keyring file (has "encrypted": true in the JSON).
// Used during load to determine whether a passphrase is needed.
func isEncryptedKeyFile(data []byte) bool {
	var enc encryptedKeyFile
	if err := json.Unmarshal(data, &enc); err != nil {
		return false
	}
	return enc.Encrypted
}

// errNoPassphrase is returned when an encrypted keyring is
// found but no passphrase was provided.
var errNoPassphrase = errors.New("keyring file is encrypted but no passphrase provided (set AEGISGATE_IOC_KEY_PASSPHRASE)")
