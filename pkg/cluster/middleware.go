// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Cluster Middleware
// =========================================================================
//
// middleware.go provides HTTP middleware for clustered deployments:
//
//   - InstanceIdMiddleware: Adds X-Instance-Id and X-Instance-Started-At
//     headers to every response, enabling load balancers to implement
//     sticky routing for MCP and A2A connections.
//   - ClusterHealthHandler: Returns aggregated cluster health information
//     including the local node's status and its view of peer nodes.
//
// v3.4.1 clustering support.
// =========================================================================
package cluster

import (
	"encoding/json"
	"net/http"
	"time"
)

// InstanceIdMiddleware adds cluster-aware headers to responses:
//   - X-Instance-Id: Unique node identifier for sticky routing
//   - X-Instance-Started-At: Node start time for health checks
//   - X-Cluster-Mode: "standalone" or "clustered" (PostgreSQL available)
//
// Load balancers can use X-Instance-Id for session affinity:
//   - Envoy: hash_policy with header "X-Instance-Id"
//   - Nginx: hash $http_x_instance_id consistent
//   - AWS ALB: stickiness with app cookie "X-Instance-Id"
func InstanceIdMiddleware(node *NodeInfo, clusterMode string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Instance-Id", node.ID)
		w.Header().Set("X-Instance-Started-At", node.StartedAt.Format(time.RFC3339))
		w.Header().Set("X-Cluster-Mode", clusterMode)
		next.ServeHTTP(w, r)
	})
}

// ClusterHealthResponse represents the health of the local node
// and its cluster membership status.
type ClusterHealthResponse struct {
	NodeID      string                 `json:"node_id"`
	Hostname    string                 `json:"hostname"`
	Version     string                 `json:"version"`
	Tier        string                 `json:"tier"`
	Uptime      string                 `json:"uptime"`
	Mode        string                 `json:"mode"`  // "standalone" or "clustered"
	Peers       map[string]string      `json:"peers"` // peer node_id -> status
	LocalHealth map[string]interface{} `json:"local_health"`
}

// ClusterHealthHandler returns the cluster health information.
// This endpoint can be used by load balancers for health checks and
// by monitoring systems to track cluster membership.
func ClusterHealthHandler(node *NodeInfo, clusterMode string, localHealth map[string]interface{}, peers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := ClusterHealthResponse{
			NodeID:      node.ID,
			Hostname:    node.Hostname,
			Version:     node.Version,
			Tier:        node.Tier,
			Uptime:      node.Uptime().String(),
			Mode:        clusterMode,
			Peers:       peers,
			LocalHealth: localHealth,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
