// SPDX-License-Identifier: Apache-2.0
package cluster_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/cluster"
)

func TestInstanceIdMiddleware(t *testing.T) {
	os.Unsetenv("AEGISGATE_NODE_ID")
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "professional")
	node := cluster.GetNode()

	handler := cluster.InstanceIdMiddleware(node, "clustered", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Instance-Id") == "" {
		t.Error("expected X-Instance-Id header to be set")
	}
	if rec.Header().Get("X-Cluster-Mode") != "clustered" {
		t.Errorf("expected X-Cluster-Mode 'clustered', got '%s'", rec.Header().Get("X-Cluster-Mode"))
	}
	if rec.Header().Get("X-Instance-Started-At") == "" {
		t.Error("expected X-Instance-Started-At header to be set")
	}
}

func TestInstanceIdMiddleware_Standalone(t *testing.T) {
	os.Unsetenv("AEGISGATE_NODE_ID")
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "community")
	node := cluster.GetNode()

	handler := cluster.InstanceIdMiddleware(node, "standalone", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Cluster-Mode") != "standalone" {
		t.Errorf("expected X-Cluster-Mode 'standalone', got '%s'", rec.Header().Get("X-Cluster-Mode"))
	}
}

func TestInstanceIdMiddleware_PassesThroughToHandler(t *testing.T) {
	os.Unsetenv("AEGISGATE_NODE_ID")
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "professional")
	node := cluster.GetNode()

	innerCalled := false
	handler := cluster.InstanceIdMiddleware(node, "clustered", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest("POST", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !innerCalled {
		t.Error("expected inner handler to be called")
	}
	if rec.Code != http.StatusAccepted {
		t.Errorf("expected status 202, got %d", rec.Code)
	}
}

func TestClusterHealthHandler(t *testing.T) {
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "professional")
	node := cluster.GetNode()

	localHealth := map[string]interface{}{
		"proxy":       map[string]interface{}{"healthy": true},
		"persistence": map[string]interface{}{"healthy": true},
	}
	peers := map[string]string{
		"node-2": "healthy",
		"node-3": "healthy",
	}

	handler := cluster.ClusterHealthHandler(node, "clustered", localHealth, peers)

	req := httptest.NewRequest("GET", "/api/v1/cluster/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp cluster.ClusterHealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Mode != "clustered" {
		t.Errorf("expected mode 'clustered', got '%s'", resp.Mode)
	}
	if len(resp.Peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(resp.Peers))
	}
	if resp.NodeID == "" {
		t.Error("expected non-empty node ID")
	}
	if resp.Version != "3.4.1" {
		t.Errorf("expected version '3.4.1', got '%s'", resp.Version)
	}
	if resp.Tier != "professional" {
		t.Errorf("expected tier 'professional', got '%s'", resp.Tier)
	}
}

func TestClusterHealthResponse_JSONFields(t *testing.T) {
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "professional")
	node := cluster.GetNode()

	localHealth := map[string]interface{}{
		"proxy": "ok",
	}
	peers := map[string]string{}

	handler := cluster.ClusterHealthHandler(node, "standalone", localHealth, peers)

	req := httptest.NewRequest("GET", "/api/v1/cluster/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}

	var resp cluster.ClusterHealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Uptime == "" {
		t.Error("expected non-empty uptime")
	}
	if resp.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
}
