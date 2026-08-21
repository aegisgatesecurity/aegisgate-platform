// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — DSAR Service Tests

package dsar

import (
	"context"
	"encoding/json"
	"testing"
)

// mockProvider is a test DataProvider.
type mockProvider struct {
	name string
	data map[string]json.RawMessage
}

func (m *mockProvider) Name() string { return m.name }

func (m *mockProvider) Export(_ context.Context, entityID string) (json.RawMessage, error) {
	if d, ok := m.data[entityID]; ok {
		return d, nil
	}
	return nil, nil
}

func (m *mockProvider) Erase(_ context.Context, entityID string) (int, error) {
	if _, ok := m.data[entityID]; ok {
		delete(m.data, entityID)
		return 1, nil
	}
	return 0, nil
}

type mockHoldChecker struct {
	underHold bool
}

func (m *mockHoldChecker) IsUnderHold(_ context.Context, entityID string) bool {
	return m.underHold
}

func TestService_Export(t *testing.T) {
	s := NewService(nil, nil)
	s.RegisterProvider(&mockProvider{
		name: "test",
		data: map[string]json.RawMessage{
			"user-1": json.RawMessage(`{"name":"Alice"}`),
		},
	})

	bundle, err := s.Export(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if bundle.EntityID != "user-1" {
		t.Fatalf("EntityID=%s, want user-1", bundle.EntityID)
	}
	if len(bundle.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(bundle.Providers))
	}
}

func TestService_Erase(t *testing.T) {
	data := map[string]json.RawMessage{
		"user-2": json.RawMessage(`{"name":"Bob"}`),
	}
	s := NewService(&mockHoldChecker{underHold: false}, nil)
	s.RegisterProvider(&mockProvider{name: "test", data: data})

	result, err := s.Erase(context.Background(), "user-2")
	if err != nil {
		t.Fatalf("Erase failed: %v", err)
	}
	if result.RecordsAffected != 1 {
		t.Fatalf("RecordsAffected=%d, want 1", result.RecordsAffected)
	}
	if result.BlockedBy != "" {
		t.Fatalf("BlockedBy=%s, want empty", result.BlockedBy)
	}
}

func TestService_Erase_BlockedByLegalHold(t *testing.T) {
	s := NewService(&mockHoldChecker{underHold: true}, nil)
	s.RegisterProvider(&mockProvider{
		name: "test",
		data: map[string]json.RawMessage{
			"user-3": json.RawMessage(`{"name":"Charlie"}`),
		},
	})

	result, err := s.Erase(context.Background(), "user-3")
	if err == nil {
		t.Fatal("expected error when under legal hold")
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.BlockedBy != "legal_hold" {
		t.Fatalf("BlockedBy=%s, want legal_hold", result.BlockedBy)
	}
}

func TestService_Export_EmptyEntityID(t *testing.T) {
	s := NewService(nil, nil)
	_, err := s.Export(context.Background(), "")
	if err == nil {
		t.Fatal("expected error on empty entity ID")
	}
}
