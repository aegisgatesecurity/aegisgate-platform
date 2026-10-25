// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Agent Registry Store Error Tests (v5.0)
//
// Tests for ErrNotFound and its Is method, which is used by the
// registry and HTTP handlers to distinguish "not found" errors from
// other failures.

package agentregistry

import (
	"errors"
	"fmt"
	"testing"
)

// TestErrNotFound_Error verifies the error message.
func TestErrNotFound_Error(t *testing.T) {
	err := ErrNotFound
	if err.Error() != "agentregistry: agent not found" {
		t.Errorf("Error() = %q, want %q", err.Error(), "agentregistry: agent not found")
	}
}

// TestErrNotFound_Is verifies that Is correctly identifies ErrNotFound.
func TestErrNotFound_Is(t *testing.T) {
	// Direct match
	if !errors.Is(ErrNotFound, ErrNotFound) {
		t.Error("errors.Is(ErrNotFound, ErrNotFound) should be true")
	}

	// Wrapped ErrNotFound
	wrapped := fmt.Errorf("wrapped: %w", ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Error("errors.Is(wrapped, ErrNotFound) should be true")
	}

	// Different error should not match
	other := fmt.Errorf("some other error")
	if errors.Is(other, ErrNotFound) {
		t.Error("errors.Is(other, ErrNotFound) should be false")
	}

	// Nil should not match
	if errors.Is(nil, ErrNotFound) {
		t.Error("errors.Is(nil, ErrNotFound) should be false")
	}

	// ErrNotFound should not match a generic error
	if errors.Is(ErrNotFound, fmt.Errorf("test")) {
		t.Error("errors.Is(ErrNotFound, generic) should be false")
	}
}

// TestErrNotFound_NilTarget verifies Is with a nil target.
func TestErrNotFound_NilTarget(t *testing.T) {
	// errors.Is with nil target returns false
	if errors.Is(ErrNotFound, nil) {
		t.Error("errors.Is(ErrNotFound, nil) should be false")
	}
}