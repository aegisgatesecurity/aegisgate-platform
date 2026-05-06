// SPDX-License-Identifier: Apache-2.0
//go:build !race

package stores

// ---------------------------------------------------------------------------
// store_test.go — Full coverage for SSO in-memory stores
// ---------------------------------------------------------------------------

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// =============================================================================
// InMemorySessionStore Tests
// =============================================================================

func TestInMemorySessionStore_Create(t *testing.T) {
	store := NewInMemorySessionStore()
	session := &Session{
		ID:        "sess-1",
		UserID:    "user-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	if err := store.Create(context.Background(), session); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Verify it was stored
	retrieved, err := store.Get(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("session should not be nil")
	}
	if retrieved.ID != "sess-1" {
		t.Errorf("ID=%q, want sess-1", retrieved.ID)
	}
}

func TestInMemorySessionStore_CreateDuplicate(t *testing.T) {
	store := NewInMemorySessionStore()
	session := &Session{
		ID:        "sess-dup",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	store.Create(context.Background(), session)
	// Overwrite by same ID — Create is a no-op (no error, just replaces)
	store.Create(context.Background(), session)
}

func TestInMemorySessionStore_Get_Missing(t *testing.T) {
	store := NewInMemorySessionStore()
	session, err := store.Get(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if session != nil {
		t.Errorf("session=%v, want nil", session)
	}
}

func TestInMemorySessionStore_Get_Expired(t *testing.T) {
	store := NewInMemorySessionStore()
	session := &Session{
		ID:        "sess-expired",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // EXPIRED
	}
	store.Create(context.Background(), session)

	// Expired sessions are auto-deleted on Get
	retrieved, err := store.Get(context.Background(), "sess-expired")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if retrieved != nil {
		t.Errorf("expired session=%v, want nil", retrieved)
	}
}

func TestInMemorySessionStore_Delete(t *testing.T) {
	store := NewInMemorySessionStore()
	store.Create(context.Background(), &Session{
		ID:        "sess-del",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	if err := store.Delete(context.Background(), "sess-del"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	session, _ := store.Get(context.Background(), "sess-del")
	if session != nil {
		t.Error("session should be deleted")
	}
}

func TestInMemorySessionStore_DeleteNonExistent(t *testing.T) {
	store := NewInMemorySessionStore()
	// Should NOT error on non-existent
	if err := store.Delete(context.Background(), "nonexistent"); err != nil {
		t.Fatalf("Delete() on nonexistent error: %v", err)
	}
}

func TestInMemorySessionStore_DeleteUserSessions(t *testing.T) {
	store := NewInMemorySessionStore()
	for i := 1; i <= 3; i++ {
		store.Create(context.Background(), &Session{
			ID:        "sess-u1-" + string(rune('0'+i)),
			UserID:    "user-1",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
	}
	store.Create(context.Background(), &Session{
		ID:        "sess-u2-1",
		UserID:    "user-2",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	if err := store.DeleteUserSessions(context.Background(), "user-1"); err != nil {
		t.Fatalf("DeleteUserSessions() error: %v", err)
	}

	for i := 1; i <= 3; i++ {
		s, _ := store.Get(context.Background(), "sess-u1-"+string(rune('0'+i)))
		if s != nil {
			t.Errorf("session sess-u1-%d should be deleted", i)
		}
	}
	// user-2's session should still exist
	s, _ := store.Get(context.Background(), "sess-u2-1")
	if s == nil {
		t.Error("user-2 session should still exist")
	}
}

func TestInMemorySessionStore_DeleteUserSessions_None(t *testing.T) {
	store := NewInMemorySessionStore()
	if err := store.DeleteUserSessions(context.Background(), "nonexistent-user"); err != nil {
		t.Fatalf("DeleteUserSessions() error: %v", err)
	}
}

func TestInMemorySessionStore_List(t *testing.T) {
	store := NewInMemorySessionStore()
	for i := 1; i <= 5; i++ {
		store.Create(context.Background(), &Session{
			ID:        "sess-list-" + string(rune('0'+i)),
			UserID:    "user-list",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
	}

	sessions, err := store.List(context.Background(), "user-list", 3, 0)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("len(sessions)=%d, want 3", len(sessions))
	}

	// Test offset beyond length
	rest, err := store.List(context.Background(), "user-list", 10, 5)
	if err != nil {
		t.Fatalf("List(offset) error: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("len(rest)=%d, want 0", len(rest))
	}
}

func TestInMemorySessionStore_List_Empty(t *testing.T) {
	store := NewInMemorySessionStore()
	sessions, err := store.List(context.Background(), "user-none", 10, 0)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("len(sessions)=%d, want 0", len(sessions))
	}
}

func TestInMemorySessionStore_Cleanup(t *testing.T) {
	store := NewInMemorySessionStore()
	// Add one expired, one valid
	store.Create(context.Background(), &Session{
		ID:        "sess-clean-expired",
		UserID:    "user-clean",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	store.Create(context.Background(), &Session{
		ID:        "sess-clean-valid",
		UserID:    "user-clean",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	count, err := store.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}
	if count != 1 {
		t.Errorf("count=%d, want 1", count)
	}

	// Valid session should still exist
	s, _ := store.Get(context.Background(), "sess-clean-valid")
	if s == nil {
		t.Error("valid session should still exist after cleanup")
	}
}

func TestInMemorySessionStore_Cleanup_NoExpired(t *testing.T) {
	store := NewInMemorySessionStore()
	store.Create(context.Background(), &Session{
		ID:        "sess-no-clean",
		UserID:    "user-clean",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	count, err := store.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}
	if count != 0 {
		t.Errorf("count=%d, want 0", count)
	}
}

func TestInMemorySessionStore_List_ExpiredExcluded(t *testing.T) {
	store := NewInMemorySessionStore()
	store.Create(context.Background(), &Session{
		ID:        "sess-exp-list",
		UserID:    "user-exp-list",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	})

	sessions, err := store.List(context.Background(), "user-exp-list", 10, 0)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expired sessions included: len=%d", len(sessions))
	}
}

func TestInMemorySessionStore_List_LimitZero(t *testing.T) {
	store := NewInMemorySessionStore()
	for i := 1; i <= 5; i++ {
		store.Create(context.Background(), &Session{
			ID:        "sess-lz-" + strconv.Itoa(i),
			UserID:    "user-lz",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
	}

	// limit=0 should trigger "end = offset + limit" → "end = offset"
	sessions, err := store.List(context.Background(), "user-lz", 0, 0)
	if err != nil {
		t.Fatalf("List(limit=0) error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("len(sessions)=%d with limit=0, want 0", len(sessions))
	}
}

func TestInMemorySessionStore_List_OffsetBeyondLength(t *testing.T) {
	store := NewInMemorySessionStore()
	store.Create(context.Background(), &Session{
		ID:        "sess-ob-1",
		UserID:    "user-ob",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	// offset > len(result) — triggers the "if offset >= len(result)" early return
	sessions, err := store.List(context.Background(), "user-ob", 10, 5)
	if err != nil {
		t.Fatalf("List(offset>beyond) error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("len(sessions)=%d with large offset, want 0", len(sessions))
	}
}

// =============================================================================
// InMemoryTokenStore Tests
// =============================================================================

func TestInMemoryTokenStore_Store(t *testing.T) {
	store := NewInMemoryTokenStore()
	token := &Token{
		ID:           "tok-1",
		UserID:       "user-1",
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	if err := store.Store(context.Background(), token); err != nil {
		t.Fatalf("Store() error: %v", err)
	}
}

func TestInMemoryTokenStore_StoreWithoutRefresh(t *testing.T) {
	store := NewInMemoryTokenStore()
	token := &Token{
		ID:          "tok-no-refresh",
		UserID:      "user-1",
		AccessToken: "access-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	if err := store.Store(context.Background(), token); err != nil {
		t.Fatalf("Store() error: %v", err)
	}
}

func TestInMemoryTokenStore_Get(t *testing.T) {
	store := NewInMemoryTokenStore()
	token := &Token{
		ID:          "tok-get",
		UserID:      "user-1",
		AccessToken: "access-get",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	store.Store(context.Background(), token)

	retrieved, err := store.Get(context.Background(), "tok-get")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("token should not be nil")
	}
	if retrieved.AccessToken != "access-get" {
		t.Errorf("AccessToken=%q, want access-get", retrieved.AccessToken)
	}
}

func TestInMemoryTokenStore_Get_Missing(t *testing.T) {
	store := NewInMemoryTokenStore()
	token, err := store.Get(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if token != nil {
		t.Errorf("token=%v, want nil", token)
	}
}

func TestInMemoryTokenStore_Get_Expired(t *testing.T) {
	store := NewInMemoryTokenStore()
	store.Store(context.Background(), &Token{
		ID:          "tok-expired",
		UserID:      "user-1",
		AccessToken: "access-expired",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	})

	retrieved, err := store.Get(context.Background(), "tok-expired")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if retrieved != nil {
		t.Errorf("expired token=%v, want nil", retrieved)
	}
}

func TestInMemoryTokenStore_GetByRefreshToken(t *testing.T) {
	store := NewInMemoryTokenStore()
	store.Store(context.Background(), &Token{
		ID:           "tok-refresh",
		UserID:       "user-1",
		AccessToken:  "access-refresh",
		RefreshToken: "my-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	token, err := store.GetByRefreshToken(context.Background(), "my-refresh-token")
	if err != nil {
		t.Fatalf("GetByRefreshToken() error: %v", err)
	}
	if token == nil {
		t.Fatal("token should not be nil")
	}
	if token.AccessToken != "access-refresh" {
		t.Errorf("AccessToken=%q, want access-refresh", token.AccessToken)
	}
}

func TestInMemoryTokenStore_GetByRefreshToken_Missing(t *testing.T) {
	store := NewInMemoryTokenStore()
	token, err := store.GetByRefreshToken(context.Background(), "nonexistent-refresh")
	if err != nil {
		t.Fatalf("GetByRefreshToken() error: %v", err)
	}
	if token != nil {
		t.Errorf("token=%v, want nil", token)
	}
}

func TestInMemoryTokenStore_GetByRefreshToken_Expired(t *testing.T) {
	store := NewInMemoryTokenStore()
	store.Store(context.Background(), &Token{
		ID:           "tok-refresh-expired",
		UserID:       "user-1",
		AccessToken:  "access-refresh-expired",
		RefreshToken: "expired-refresh-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	})

	token, err := store.GetByRefreshToken(context.Background(), "expired-refresh-token")
	if err != nil {
		t.Fatalf("GetByRefreshToken() error: %v", err)
	}
	if token != nil {
		t.Errorf("expired token=%v, want nil", token)
	}
}

func TestInMemoryTokenStore_Delete(t *testing.T) {
	store := NewInMemoryTokenStore()
	store.Store(context.Background(), &Token{
		ID:           "tok-del",
		UserID:       "user-1",
		AccessToken:  "access-del",
		RefreshToken: "refresh-del",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	if err := store.Delete(context.Background(), "tok-del"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	tok, _ := store.Get(context.Background(), "tok-del")
	if tok != nil {
		t.Error("token should be deleted")
	}
}

func TestInMemoryTokenStore_Delete_NonExistent(t *testing.T) {
	store := NewInMemoryTokenStore()
	if err := store.Delete(context.Background(), "nonexistent"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
}

func TestInMemoryTokenStore_DeleteUserTokens(t *testing.T) {
	store := NewInMemoryTokenStore()
	for i := 1; i <= 2; i++ {
		store.Store(context.Background(), &Token{
			ID:           "tok-user1-" + string(rune('0'+i)),
			UserID:       "user-1",
			AccessToken:  "access-u1-" + string(rune('0'+i)),
			RefreshToken: "refresh-u1-" + string(rune('0'+i)),
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		})
	}
	store.Store(context.Background(), &Token{
		ID:          "tok-user2",
		UserID:      "user-2",
		AccessToken: "access-user2",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	if err := store.DeleteUserTokens(context.Background(), "user-1"); err != nil {
		t.Fatalf("DeleteUserTokens() error: %v", err)
	}

	for i := 1; i <= 2; i++ {
		tok, _ := store.Get(context.Background(), "tok-user1-"+string(rune('0'+i)))
		if tok != nil {
			t.Errorf("token tok-user1-%d should be deleted", i)
		}
	}
	// user-2 token should still exist
	tok, _ := store.Get(context.Background(), "tok-user2")
	if tok == nil {
		t.Error("user-2 token should still exist")
	}
}

func TestInMemoryTokenStore_Cleanup(t *testing.T) {
	store := NewInMemoryTokenStore()
	store.Store(context.Background(), &Token{
		ID:           "tok-clean-exp",
		UserID:       "user-clean",
		AccessToken:  "access-clean-exp",
		RefreshToken: "refresh-clean-exp",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	})
	store.Store(context.Background(), &Token{
		ID:          "tok-clean-valid",
		UserID:      "user-clean",
		AccessToken: "access-clean-valid",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	count, err := store.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}
	if count != 1 {
		t.Errorf("count=%d, want 1", count)
	}
}

func TestInMemoryTokenStore_Cleanup_NoExpired(t *testing.T) {
	store := NewInMemoryTokenStore()
	store.Store(context.Background(), &Token{
		ID:          "tok-no-clean",
		UserID:      "user-no-clean",
		AccessToken: "access-no-clean",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	count, err := store.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}
	if count != 0 {
		t.Errorf("count=%d, want 0", count)
	}
}
