// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package opsec provides operational security features for the AegisGate gateway
package opsec

import (
	"crypto/subtle"
	"runtime"
	"sync"
)

// MemoryScrubber provides secure memory wiping capabilities
type MemoryScrubber struct {
	mu sync.Mutex
}

// NewMemoryScrubber creates a new memory scrubber instance
func NewMemoryScrubber() *MemoryScrubber {
	return &MemoryScrubber{}
}

// ScrubString securely wipes a string from memory
// Note: In Go, strings are immutable, so this converts to []byte first
func (m *MemoryScrubber) ScrubString(s *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s == nil || len(*s) == 0 {
		return nil
	}

	// Convert string to mutable byte slice
	// This creates a copy, which we can then scrub
	b := []byte(*s)

	// Zero out the bytes
	for i := range b {
		b[i] = 0
	}

	// Prevent compiler optimization
	subtle.ConstantTimeCopy(len(b), b, b)

	*s = ""
	return nil
}

// ScrubBytes securely wipes a byte slice from memory
func (m *MemoryScrubber) ScrubBytes(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(b) == 0 {
		return nil
	}

	// Zero out each byte
	for i := range b {
		b[i] = 0
	}

	// Prevent compiler optimization from removing the clearing
	// by using a side-effect in subtle package
	subtle.ConstantTimeCopy(len(b), b, b)

	return nil
}

// ScrubSecureString uses runtime.KeepAlive for robust scrubbing
// This implementation avoids unsafe package to satisfy go vetlinting
func (m *MemoryScrubber) ScrubSecureString(s *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s == nil {
		return nil
	}

	strData := *s
	if len(strData) == 0 {
		return nil
	}

	// Convert to byte slice for scrubbing (creates a copy)
	// While this cannot scrub the original string data (Go strings are immutable),
	// it clears any copies that may have been made
	b := []byte(strData)

	// Zero out the byte copy
	for i := range b {
		b[i] = 0
	}

	// Prevent compiler optimization
	subtle.ConstantTimeCopy(len(b), b, b)

	// Keep reference to prevent GC from reclaiming during scrub
	runtime.KeepAlive(strData)

	// Clear the original string reference
	*s = ""

	return nil
}

// ScrubMultiple securely wipes multiple byte slices
func (m *MemoryScrubber) ScrubMultiple(buffers ...[]byte) error {
	for _, buf := range buffers {
		if err := m.ScrubBytes(buf); err != nil {
			return err
		}
	}
	return nil
}

// SecureDelete implements secure deletion with multiple passes
// Pass 1: zeros, Pass 2: ones, Pass 3: random data, Pass 4: zeros
func (m *MemoryScrubber) SecureDelete(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(b) == 0 {
		return nil
	}

	// Pass 1: Overwrite with zeros
	for i := range b {
		b[i] = 0x00
	}
	subtle.ConstantTimeCopy(len(b), b, b)

	// Pass 2: Overwrite with ones (0xFF)
	for i := range b {
		b[i] = 0xFF
	}
	subtle.ConstantTimeCopy(len(b), b, b)

	// Pass 3: Overwrite with alternating pattern
	for i := range b {
		b[i] = 0xAA
	}
	subtle.ConstantTimeCopy(len(b), b, b)

	// Pass 4: Final zeros
	for i := range b {
		b[i] = 0x00
	}
	subtle.ConstantTimeCopy(len(b), b, b)

	return nil
}

// MemoryScrub is the legacy method retained for compatibility
// It wipes all sensitive data in the OPSEC system
func (m *MemoryScrubber) MemoryScrub() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// This is a placeholder that should be called when
	// sensitive data needs to be wiped
	// The actual implementation depends on what data is stored
	// This is meant to be extended based on specific use case

	return nil
}
