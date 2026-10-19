// SPDX-License-Identifier: Apache-2.0

package ioc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockTAXIIServer creates a test HTTP server that responds to TAXII 2.1
// endpoints: discovery, collections, and objects.
func mockTAXIIServer(t *testing.T, emptyBundle bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Discovery endpoint
	mux.HandleFunc("/taxii2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json")
		resp := map[string]interface{}{
			"title":     "Mock TAXII Server",
			"api_roots": []string{r.URL.Scheme + "://" + r.URL.Host + "/api-root"},
		}
		json.NewEncoder(w).Encode(resp)
	})

	// Collections endpoint
	mux.HandleFunc("/api-root/collections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json")
		resp := map[string]interface{}{
			"collections": []map[string]interface{}{
				{"id": "col-1", "title": "Test Collection", "can_read": true, "can_write": true},
			},
		}
		json.NewEncoder(w).Encode(resp)
	})

	// Objects endpoint (GET = Pull, POST = Push)
	mux.HandleFunc("/api-root/collections/col-1/objects", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json")
		if r.Method == http.MethodPost {
			// AddObjects response
			resp := map[string]interface{}{
				"objects": []interface{}{},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		// GetObjects response — STIX bundle
		if emptyBundle {
			resp := map[string]interface{}{
				"type":    "bundle",
				"id":      "bundle--test-1",
				"objects": []interface{}{},
			}
			json.NewEncoder(w).Encode(resp)
		} else {
			// Return a STIX indicator that can be converted to an IOC
			resp := map[string]interface{}{
				"type": "bundle",
				"id":   "bundle--test-2",
				"objects": []interface{}{
					map[string]interface{}{
						"type":         "indicator",
						"id":           "indicator--test-1",
						"pattern":      "[file:hashes.'SHA-256' = 'abc123']",
						"pattern_type": "stix",
						"valid_from":   time.Now().UTC().Format(time.RFC3339),
						"labels":       []string{"malicious-activity"},
						"custom_properties": []map[string]interface{}{
							{"aegisgate_type": "proxy_response"},
							{"aegisgate_severity": "high"},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	})

	return httptest.NewServer(mux)
}

func TestPhase3_TAXII_Discovery(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "token",
		APIToken:  "test-token",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	disc, err := ti.Discovery(context.Background())
	if err != nil {
		t.Fatalf("Discovery: %v", err)
	}
	if disc.Title != "Mock TAXII Server" {
		t.Fatalf("expected title='Mock TAXII Server', got %s", disc.Title)
	}
	if len(disc.APIRoots) != 1 {
		t.Fatalf("expected 1 API root, got %d", len(disc.APIRoots))
	}
}

func TestPhase3_TAXII_GetCollections(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "token",
		APIToken:  "test-token",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	apiRoot := srv.URL + "/api-root"
	cols, err := ti.GetCollections(context.Background(), apiRoot)
	if err != nil {
		t.Fatalf("GetCollections: %v", err)
	}
	if len(cols.Collections) != 1 {
		t.Fatalf("expected 1 collection, got %d", len(cols.Collections))
	}
	if cols.Collections[0].ID != "col-1" {
		t.Fatalf("expected collection ID=col-1, got %s", cols.Collections[0].ID)
	}
}

func TestPhase3_TAXII_GetCollections_EmptyAPIRoot(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "token",
		APIToken:  "test-token",
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	_, err = ti.GetCollections(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty apiRoot")
	}
}

func TestPhase3_TAXII_Pull_EmptyBundle(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "token",
		APIToken:  "test-token",
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	apiRoot := srv.URL + "/api-root"
	bundle, err := ti.Pull(context.Background(), apiRoot, "col-1", time.Time{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if bundle == nil {
		t.Fatal("expected non-nil bundle")
	}
}

func TestPhase3_TAXII_Pull_EmptyAPIRoot(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "token",
		APIToken:  "test-token",
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	_, err = ti.Pull(context.Background(), "", "col-1", time.Time{})
	if err == nil {
		t.Fatal("expected error for empty apiRoot")
	}
}

func TestPhase3_TAXII_Pull_WithDefaultCollection(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL:         srv.URL,
		AuthType:          "token",
		APIToken:          "test-token",
		DefaultCollection: "col-1",
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	apiRoot := srv.URL + "/api-root"
	// Pull with empty collectionID — should use DefaultCollection
	bundle, err := ti.Pull(context.Background(), apiRoot, "", time.Time{})
	if err != nil {
		t.Fatalf("Pull with default collection: %v", err)
	}
	if bundle == nil {
		t.Fatal("expected non-nil bundle")
	}
}

func TestPhase3_TAXII_Push_NilBundle(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "token",
		APIToken:  "test-token",
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	_, err = ti.Push(context.Background(), nil, "api-root", "col-1")
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPhase3_TAXII_Push_EmptyAPIRoot(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "token",
		APIToken:  "test-token",
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	bundle := NewBundle("test-source")
	_, err = ti.Push(context.Background(), bundle, "", "col-1")
	if err == nil {
		t.Fatal("expected error for empty apiRoot")
	}
}

func TestPhase3_TAXII_Push_EmptyCollectionID(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "token",
		APIToken:  "test-token",
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	bundle := NewBundle("test-source")
	apiRoot := srv.URL + "/api-root"
	_, err = ti.Push(context.Background(), bundle, apiRoot, "")
	if err == nil {
		t.Fatal("expected error for empty collectionID with no default")
	}
}

func TestPhase3_TAXII_Push_WithDefaultCollection(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	ti, err := NewTAXIIIntegration(TAXIIIntegrationConfig{
		ServerURL:         srv.URL,
		AuthType:          "token",
		APIToken:          "test-token",
		DefaultCollection: "col-1",
	})
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer ti.Close()

	bundle := NewBundle("test-source")
	apiRoot := srv.URL + "/api-root"
	_, err = ti.Push(context.Background(), bundle, apiRoot, "")
	if err != nil {
		t.Fatalf("Push with default collection: %v", err)
	}
}

// =====================================================================
// FeedManager Run/pullFeed tests with mock TAXII server
// =====================================================================

func TestPhase3_FeedManager_RunAndStop(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fm, err := NewFeedManager(store, []FeedConfig{
		{
			Name:          "test-feed",
			ServerURL:     srv.URL,
			AuthType:      "token",
			APIToken:      "test-token",
			APIRoot:       srv.URL + "/api-root",
			CollectionID:  "col-1",
			PollInterval:  100 * time.Millisecond,
			Enabled:       true,
			SeverityFloor: SeverityLow,
		},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run in a goroutine
	go fm.Run(ctx)

	// Give it time to do an initial pull
	time.Sleep(300 * time.Millisecond)

	// Stop the feed manager
	fm.Stop()
	cancel()

	// Verify stats
	allStats := fm.Stats()
	if len(allStats) == 0 {
		t.Fatal("expected at least 1 feed stats")
	}
	found := false
	for _, s := range allStats {
		if s.Name == "test-feed" && s.TotalPulls >= 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected test-feed with at least 1 pull")
	}
}

func TestPhase3_FeedManager_RunDisabledFeed(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fm, err := NewFeedManager(store, []FeedConfig{
		{
			Name:         "disabled-feed",
			ServerURL:    srv.URL,
			AuthType:     "token",
			APIToken:     "test-token",
			CollectionID: "col-1",
			Enabled:      false,
		},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run should complete immediately since no feeds are enabled
	done := make(chan struct{})
	go func() {
		fm.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Good — Run returned immediately
	case <-time.After(2 * time.Second):
		t.Fatal("Run hung with disabled feed")
	}

	fm.Stop()
}

func TestPhase3_FeedManager_PullNow(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()

	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fm, err := NewFeedManager(store, []FeedConfig{
		{
			Name:          "pullnow-feed",
			ServerURL:     srv.URL,
			AuthType:      "token",
			APIToken:      "test-token",
			APIRoot:       srv.URL + "/api-root",
			CollectionID:  "col-1",
			PollInterval:  10 * time.Second,
			Enabled:       true,
			SeverityFloor: SeverityLow,
		},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	// PullNow should trigger an immediate pull
	_, err = fm.PullNow(context.Background(), "pullnow-feed")
	if err != nil {
		t.Fatalf("PullNow: %v", err)
	}
}

func TestPhase3_FeedManager_PullNow_NotFound(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fm, err := NewFeedManager(store, nil)
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	_, err = fm.PullNow(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent feed")
	}
}
