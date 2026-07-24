// SPDX-License-Identifier: Apache-2.0
package cluster_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/cluster"
)

func TestInitNode_WithEnvVar(t *testing.T) {
	os.Setenv("AEGISGATE_NODE_ID", "test-node-1")
	defer os.Unsetenv("AEGISGATE_NODE_ID")

	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "professional")
	node := cluster.GetNode()

	if node.ID != "test-node-1" {
		t.Errorf("expected node ID 'test-node-1', got '%s'", node.ID)
	}
	if node.Version != "3.4.1" {
		t.Errorf("expected version '3.4.1', got '%s'", node.Version)
	}
	if node.Tier != "professional" {
		t.Errorf("expected tier 'professional', got '%s'", node.Tier)
	}
}

func TestInitNode_WithoutEnvVar(t *testing.T) {
	os.Unsetenv("AEGISGATE_NODE_ID")

	// Reset global for this test
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "community")
	node := cluster.GetNode()

	if node.ID == "" {
		t.Error("expected non-empty generated node ID")
	}
	if len(node.ID) != 16 { // 8 random bytes = 16 hex chars
		t.Errorf("expected 16-char hex ID, got '%s' (len=%d)", node.ID, len(node.ID))
	}
}

func TestGetNode_AutoInit(t *testing.T) {
	// GetNode should auto-initialize if InitNode was not called
	cluster.ResetForTest()
	node := cluster.GetNode()

	if node == nil {
		t.Error("expected non-nil node from GetNode auto-init")
	}
	if node.ID == "" {
		t.Error("expected non-empty auto-generated node ID")
	}
	if node.Version != "unknown" {
		t.Errorf("expected default version 'unknown', got '%s'", node.Version)
	}
	if node.Tier != "unknown" {
		t.Errorf("expected default tier 'unknown', got '%s'", node.Tier)
	}
}

func TestNodeString(t *testing.T) {
	os.Setenv("AEGISGATE_NODE_ID", "abc123def456")
	defer os.Unsetenv("AEGISGATE_NODE_ID")

	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "community")
	node := cluster.GetNode()

	s := node.String()
	if len(s) == 0 {
		t.Error("expected non-empty node string")
	}
	// String format: "aegisgate-<first8>@<hostname>"
	if !strings.HasPrefix(s, "aegisgate-") {
		t.Errorf("expected string to start with 'aegisgate-', got '%s'", s)
	}
}

func TestNodeUptime(t *testing.T) {
	os.Unsetenv("AEGISGATE_NODE_ID")
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "community")
	node := cluster.GetNode()

	uptime := node.Uptime()
	if uptime < 0 {
		t.Error("uptime should not be negative")
	}
	// Uptime should be very small (just created)
	if uptime > 5*time.Second {
		t.Error("uptime should be small for just-created node")
	}
}

func TestNodeHostname(t *testing.T) {
	os.Unsetenv("AEGISGATE_NODE_ID")
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "community")
	node := cluster.GetNode()

	if node.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
}

func TestNodeStartedAt(t *testing.T) {
	os.Unsetenv("AEGISGATE_NODE_ID")
	cluster.ResetForTest()
	cluster.InitNode("3.4.1", "community")
	node := cluster.GetNode()

	if node.StartedAt.IsZero() {
		t.Error("expected non-zero StartedAt time")
	}
	// StartedAt should be recent (within the last 5 seconds)
	if time.Since(node.StartedAt) > 5*time.Second {
		t.Error("StartedAt should be recent")
	}
}
