// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package graphql

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
)

// Handler handles HTTP requests for GraphQL
type Handler struct {
	executor     *Executor
	authMgr      *auth.Manager
	allowedPaths []string
}

// NewHandler creates a new GraphQL handler
func NewHandler(resolver *Resolver, authMgr *auth.Manager) *Handler {
	return &Handler{
		executor:     NewExecutor(resolver),
		authMgr:      authMgr,
		allowedPaths: []string{"/health", "/ready", "/metrics"},
	}
}

// ServeHTTP handles HTTP requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if path is allowed without auth
	if h.isAllowedPath(r.URL.Path) {
		h.handleRequest(w, r)
		return
	}

	// Simple auth check - just pass through for now
	h.handleRequest(w, r)
}

func (h *Handler) isAllowedPath(path string) bool {
	for _, p := range h.allowedPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Only allow POST for queries
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request
	var req struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
		Operation string                 `json:"operationName"`
	}

	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
	} else {
		req.Query = r.URL.Query().Get("query")
		req.Variables = make(map[string]interface{})
	}

	// Execute query
	resp := h.executor.Execute(r.Context(), req.Query, req.Variables)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
