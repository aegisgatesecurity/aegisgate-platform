// SPDX-License-Identifier: Apache-2.0
// Phase 4 unit tests for cluster package — covers String short ID path,
// ClusterHealthHandler with nil peers, and other edge cases.

package cluster_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/cluster"
)

// String with short ID (< 8 chars) should use full ID
func TestPhase4_NodeString_ShortID(t *testing.T) {
	os.Setenv("AEGISGATE_NODE_ID", "abc")
	defer os.Unsetenv("AEGISGATE_NODE_ID")
	cluster.ResetForTest()
	cluster.InitNode("4.0.0", "community")
	node := cluster.GetNode()

	s := node.String()
	if !strings.HasPrefix(s, "aegisgate-abc@") {
		t.Errorf("expected 'aegisgate-abc@hostname' for short ID, got %q", s)
	}
}

func TestPhase4_ClusterHealthHandler_NilPeers(t *testing.T) {
	cluster.ResetForTest()
	cluster.InitNode("4.0.0", "professional")
	node := cluster.GetNode()

	handler := cluster.ClusterHealthHandler(node, "standalone", nil, nil)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestPhase4_ClusterHealthHandler_EmptyHealth(t *testing.T) {
	cluster.ResetForTest()
	cluster.InitNode("4.0.0", "community")
	node := cluster.GetNode()

	handler := cluster.ClusterHealthHandler(node, "standalone", map[string]interface{}{}, map[string]string{})

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
