// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Cluster Node Identity
// =========================================================================
package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

// NodeInfo identifies a single instance in a cluster.
// The ID is stable across restarts when AEGISGATE_NODE_ID is set,
// or generated randomly per-process otherwise.
type NodeInfo struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	StartedAt time.Time `json:"started_at"`
	Version   string    `json:"version"`
	Tier      string    `json:"tier"`
	mu        sync.RWMutex
}

// global node info — set once at startup
var (
	globalNode *NodeInfo
	once       sync.Once
)

// InitNode initializes the global NodeInfo. Call once at startup.
// If AEGISGATE_NODE_ID is set, it is used as the stable node ID
// (recommended for clustered deployments). Otherwise, a random ID
// is generated per-process.
func InitNode(version, tier string) {
	once.Do(func() {
		nodeID := os.Getenv("AEGISGATE_NODE_ID")
		if nodeID == "" {
			b := make([]byte, 8)
			rand.Read(b) //nosec G404 -- not cryptographic, just unique
			nodeID = hex.EncodeToString(b)
		}
		hostname, _ := os.Hostname()

		globalNode = &NodeInfo{
			ID:        nodeID,
			Hostname:  hostname,
			StartedAt: time.Now().UTC(),
			Version:   version,
			Tier:      tier,
		}
	})
}

// GetNode returns the global NodeInfo. Returns a default if InitNode
// has not been called.
func GetNode() *NodeInfo {
	if globalNode == nil {
		InitNode("unknown", "unknown")
	}
	return globalNode
}

// String returns a human-readable node identifier.
func (n *NodeInfo) String() string {
	return fmt.Sprintf("aegisgate-%s@%s", n.ID[:8], n.Hostname)
}

// Uptime returns the duration since the node started.
func (n *NodeInfo) Uptime() time.Duration {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return time.Since(n.StartedAt)
}

// ResetForTest resets the global node info. Only for testing.
func ResetForTest() {
	globalNode = nil
	once = sync.Once{}
}
