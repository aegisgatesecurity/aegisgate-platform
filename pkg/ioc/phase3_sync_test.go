// SPDX-License-Identifier: Apache-2.0

package ioc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

func setupTestSync(t *testing.T) *Sync {
	t.Helper()
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sync, err := NewSync(SyncConfig{
		InstanceID:         "test-instance",
		SigningKey:         key,
		KeyID:              "test-key-1",
		Store:              store,
		Tier:               tier.TierProfessional,
		EnableShare:        true,
		EnableReceive:      true,
		ClientTimeout:      5 * 1000000000, // 5s in ns
		GossipInterval:     60 * 1000000000,
		RateLimitPerMinute: 60,
	})
	if err != nil {
		t.Fatalf("NewSync: %v", err)
	}
	return sync
}

func TestPhase3_Sync_Health_ShareDisabled(t *testing.T) {
	sync := setupTestSync(t)
	sync.SetShare(false)

	handler := sync.Handler()
	req := httptest.NewRequest("GET", "/api/v1/ioc/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestPhase3_Sync_Health_ShareEnabled(t *testing.T) {
	sync := setupTestSync(t)
	sync.SetShare(true)

	handler := sync.Handler()
	req := httptest.NewRequest("GET", "/api/v1/ioc/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPhase3_Sync_Health_MethodNotAllowed(t *testing.T) {
	sync := setupTestSync(t)

	handler := sync.Handler()
	req := httptest.NewRequest("POST", "/api/v1/ioc/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestPhase3_Sync_Manifest_ShareDisabled(t *testing.T) {
	sync := setupTestSync(t)
	sync.SetShare(false)

	handler := sync.Handler()
	req := httptest.NewRequest("GET", "/api/v1/ioc/manifest", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestPhase3_Sync_Manifest_MethodNotAllowed(t *testing.T) {
	sync := setupTestSync(t)

	handler := sync.Handler()
	req := httptest.NewRequest("POST", "/api/v1/ioc/manifest", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestPhase3_Sync_AddDiscoveredPeer(t *testing.T) {
	sync := setupTestSync(t)

	sync.AddDiscoveredPeer("http://peer1:8080")
	sync.AddDiscoveredPeer("http://peer2:8080")
	// Adding duplicate should be no-op
	sync.AddDiscoveredPeer("http://peer1:8080")
}

func TestPhase3_Sync_AddDiscoveredPeer_Empty(t *testing.T) {
	sync := setupTestSync(t)
	// Empty peer URL should be no-op
	sync.AddDiscoveredPeer("")
}

func TestPhase3_Sync_SetShare(t *testing.T) {
	sync := setupTestSync(t)

	sync.SetShare(false)
	if sync.IsShare() {
		t.Fatal("expected share=false after SetShare(false)")
	}

	sync.SetShare(true)
	if !sync.IsShare() {
		t.Fatal("expected share=true after SetShare(true)")
	}
}

func TestPhase3_Sync_SetReceive(t *testing.T) {
	sync := setupTestSync(t)

	sync.SetReceive(false)
	if sync.IsReceive() {
		t.Fatal("expected receive=false after SetReceive(false)")
	}

	sync.SetReceive(true)
	if !sync.IsReceive() {
		t.Fatal("expected receive=true after SetReceive(true)")
	}
}

func TestPhase3_Sync_IsShare(t *testing.T) {
	sync := setupTestSync(t)
	if !sync.IsShare() {
		t.Fatal("expected share=true by default")
	}
}
