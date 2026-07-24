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

func TestClusterHealthHandler(t *testing.T) {
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "professional")
	node := cluster.GetNode()

	localHealth := map[string]interface{}{
		"proxy":      map[string]interface{}{"healthy": true},
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
}