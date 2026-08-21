// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Legal Hold Service Tests

package legalhold

import (
	"context"
	"testing"
)

func TestService_CreateHold(t *testing.T) {
	s := NewService()
	hold, err := s.CreateHold(context.Background(), "user-123", "user", "Case #CV-2026-001", "admin@corp.com")
	if err != nil {
		t.Fatalf("CreateHold failed: %v", err)
	}
	if hold.ID == "" {
		t.Fatal("hold ID is empty")
	}
	if !hold.IsActive() {
		t.Fatal("new hold should be active")
	}
}

func TestService_IsUnderHold(t *testing.T) {
	s := NewService()
	ctx := context.Background()

	if s.IsUnderHold(ctx, "user-123") {
		t.Fatal("should not be under hold before creation")
	}

	_, _ = s.CreateHold(ctx, "user-123", "user", "Case #1", "admin")
	if !s.IsUnderHold(ctx, "user-123") {
		t.Fatal("should be under hold after creation")
	}
}

func TestService_ReleaseHold(t *testing.T) {
	s := NewService()
	ctx := context.Background()

	hold, _ := s.CreateHold(ctx, "user-456", "user", "Case #2", "admin")
	if !s.IsUnderHold(ctx, "user-456") {
		t.Fatal("should be under hold")
	}

	if err := s.ReleaseHold(ctx, hold.ID); err != nil {
		t.Fatalf("ReleaseHold failed: %v", err)
	}

	if s.IsUnderHold(ctx, "user-456") {
		t.Fatal("should not be under hold after release")
	}
}

func TestService_GetActiveHolds(t *testing.T) {
	s := NewService()
	ctx := context.Background()

	_, _ = s.CreateHold(ctx, "user-789", "user", "Case #3", "admin")
	_, _ = s.CreateHold(ctx, "user-789", "user", "Case #4", "admin")

	holds := s.GetActiveHolds(ctx, "user-789")
	if len(holds) != 2 {
		t.Fatalf("expected 2 active holds, got %d", len(holds))
	}
}

func TestService_CreateHold_Validation(t *testing.T) {
	s := NewService()
	ctx := context.Background()

	_, err := s.CreateHold(ctx, "", "user", "reason", "admin")
	if err == nil {
		t.Fatal("should error on empty entityID")
	}

	_, err = s.CreateHold(ctx, "user-1", "user", "", "admin")
	if err == nil {
		t.Fatal("should error on empty reason")
	}
}
