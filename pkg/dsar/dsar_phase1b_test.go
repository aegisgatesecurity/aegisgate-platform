// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — DSAR Service Phase 1b Tests
//
// Additional unit tests covering error paths, edge cases, and nil
// handling for the Export and Erase functions.

package dsar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// errProvider is a DataProvider that always returns an error.
type errProvider struct {
	name string
}

func (e *errProvider) Name() string { return e.name }
func (e *errProvider) Export(_ context.Context, _ string) (json.RawMessage, error) {
	return nil, errors.New("export error")
}
func (e *errProvider) Erase(_ context.Context, _ string) (int, error) {
	return 0, errors.New("erase error")
}

// nilDataProvider is a DataProvider that always returns nil data / zero affected.
type nilDataProvider struct {
	name string
}

func (n *nilDataProvider) Name() string { return n.name }
func (n *nilDataProvider) Export(_ context.Context, _ string) (json.RawMessage, error) {
	return nil, nil
}
func (n *nilDataProvider) Erase(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// TestPhase1bExport_ProviderError covers the branch where a provider's
// Export returns an error — the service should log and continue.
func TestPhase1bExport_ProviderError(t *testing.T) {
	s := NewService(nil, nil)
	s.RegisterProvider(&errProvider{name: "failing"})

	bundle, err := s.Export(context.Background(), "user-err")
	if err != nil {
		t.Fatalf("Export should not fail when provider errors: %v", err)
	}
	if bundle == nil {
		t.Fatal("bundle should not be nil")
	}
	if len(bundle.Providers) != 0 {
		t.Fatalf("expected 0 providers, got %d", len(bundle.Providers))
	}
}

// TestPhase1bExport_NilData covers the branch where a provider returns
// nil data — it should be skipped (not added to bundle).
func TestPhase1bExport_NilData(t *testing.T) {
	s := NewService(nil, nil)
	s.RegisterProvider(&nilDataProvider{name: "nilprov"})

	bundle, err := s.Export(context.Background(), "user-nil")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if len(bundle.Providers) != 0 {
		t.Fatalf("expected 0 providers with nil data, got %d", len(bundle.Providers))
	}
}

// TestPhase1bExport_MixedProviders exercises a mix of good, erroring,
// and nil-data providers in a single Export call.
func TestPhase1bExport_MixedProviders(t *testing.T) {
	s := NewService(nil, nil)
	s.RegisterProvider(&mockProvider{
		name: "good",
		data: map[string]json.RawMessage{
			"user-mix": json.RawMessage(`{"ok":true}`),
		},
	})
	s.RegisterProvider(&errProvider{name: "bad"})
	s.RegisterProvider(&nilDataProvider{name: "nil"})

	bundle, err := s.Export(context.Background(), "user-mix")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if len(bundle.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(bundle.Providers))
	}
}

// TestPhase1bExport_NoProviders verifies Export works with zero providers.
func TestPhase1bExport_NoProviders(t *testing.T) {
	s := NewService(nil, nil)

	bundle, err := s.Export(context.Background(), "user-solo")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if len(bundle.Providers) != 0 {
		t.Fatalf("expected 0 providers, got %d", len(bundle.Providers))
	}
}

// TestPhase1bErase_NilHoldChecker covers the branch where holdCheck is
// nil — the legal hold check should be skipped entirely.
func TestPhase1bErase_NilHoldChecker(t *testing.T) {
	s := NewService(nil, nil) // holdCheck is nil
	s.RegisterProvider(&mockProvider{
		name: "test",
		data: map[string]json.RawMessage{
			"user-nil-hold": json.RawMessage(`{"x":1}`),
		},
	})

	result, err := s.Erase(context.Background(), "user-nil-hold")
	if err != nil {
		t.Fatalf("Erase failed: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.RecordsAffected != 1 {
		t.Fatalf("RecordsAffected=%d, want 1", result.RecordsAffected)
	}
	if result.BlockedBy != "" {
		t.Fatalf("BlockedBy=%s, want empty", result.BlockedBy)
	}
}

// TestPhase1bErase_ProviderError covers the branch where a provider's
// Erase returns an error — the service should log and continue.
func TestPhase1bErase_ProviderError(t *testing.T) {
	s := NewService(&mockHoldChecker{underHold: false}, nil)
	s.RegisterProvider(&errProvider{name: "failing"})

	result, err := s.Erase(context.Background(), "user-err")
	if err != nil {
		t.Fatalf("Erase should not fail when provider errors: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.RecordsAffected != 0 {
		t.Fatalf("RecordsAffected=%d, want 0", result.RecordsAffected)
	}
}

// TestPhase1bErase_EmptyEntityID verifies Erase rejects empty entity IDs.
func TestPhase1bErase_EmptyEntityID(t *testing.T) {
	s := NewService(&mockHoldChecker{underHold: false}, nil)
	_, err := s.Erase(context.Background(), "")
	if err == nil {
		t.Fatal("expected error on empty entity ID")
	}
}

// TestPhase1bErase_NilDataFromErase covers a provider returning zero
// affected records during erasure.
func TestPhase1bErase_NilDataFromErase(t *testing.T) {
	s := NewService(&mockHoldChecker{underHold: false}, nil)
	s.RegisterProvider(&nilDataProvider{name: "nilprov"})

	result, err := s.Erase(context.Background(), "user-nil")
	if err != nil {
		t.Fatalf("Erase failed: %v", err)
	}
	if result.RecordsAffected != 0 {
		t.Fatalf("RecordsAffected=%d, want 0", result.RecordsAffected)
	}
	if v, ok := result.Providers["nilprov"]; !ok || v != 0 {
		t.Fatalf("expected nilprov=0 in providers map, got %v", v)
	}
}

// TestPhase1bErase_NoProviders verifies Erase works with zero providers.
func TestPhase1bErase_NoProviders(t *testing.T) {
	s := NewService(&mockHoldChecker{underHold: false}, nil)

	result, err := s.Erase(context.Background(), "user-solo")
	if err != nil {
		t.Fatalf("Erase failed: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.RecordsAffected != 0 {
		t.Fatalf("RecordsAffected=%d, want 0", result.RecordsAffected)
	}
}

// TestPhase1bRegisterProvider_Multiple verifies multiple providers can
// be registered and are stored in order.
func TestPhase1bRegisterProvider_Multiple(t *testing.T) {
	s := NewService(nil, nil)
	s.RegisterProvider(&mockProvider{name: "a", data: map[string]json.RawMessage{}})
	s.RegisterProvider(&mockProvider{name: "b", data: map[string]json.RawMessage{}})
	s.RegisterProvider(&mockProvider{name: "c", data: map[string]json.RawMessage{}})

	if len(s.providers) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(s.providers))
	}
	if s.providers[0].Name() != "a" {
		t.Fatalf("first provider name=%s, want a", s.providers[0].Name())
	}
	if s.providers[2].Name() != "c" {
		t.Fatalf("third provider name=%s, want c", s.providers[2].Name())
	}
}
