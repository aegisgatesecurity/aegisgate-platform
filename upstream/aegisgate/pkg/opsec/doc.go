// Package opsec provides operational security features for the AegisGate gateway
// including secure audit logging, secret rotation, memory scrubbing, threat modeling,
// and runtime hardening.
//
// The OPSEC module implements security controls recommended by NIST SP 800-53 and
// follows secure coding practices for Go applications handling sensitive data.
//
// Basic Usage:
//
//	opsecManager := opsec.New()
//	opsecManager.EnableAudit()
//	opsecManager.LogAudit("session_start", map[string]string{
//	    "user": "admin",
//	    "ip": "192.168.1.1",
//	})
//
// Features:
//
// - Audit Logging: Thread-safe audit trail with integrity verification
// - Secret Rotation: Automatic or manual secret rotation with configurable periods
// - Memory Scrubbing: Secure memory wiping to prevent data leakage
// - Threat Modeling: LLM/AI-specific threat vector catalog
// - Runtime Hardening: ASLR checks, capability dropping, seccomp profiles
//
// Thread Safety:
// All OPSEC components are thread-safe and can be safely used concurrently
// from multiple goroutines.
//
// Security Considerations:
// - Secrets are stored in memory as base64-encoded strings
// - Memory scrubbing uses crypto/subtle to prevent compiler optimizations
// - Audit logs are integrity-protected with SHA-256 hashes
// - Secret rotation uses crypto/rand for cryptographic randomness
//
// License:
// This package is part of the AegisGate security gateway and follows the same
// licensing terms as the main project.
package opsec

// Version holds the current OPSEC module version
const Version = "1.0.0"
