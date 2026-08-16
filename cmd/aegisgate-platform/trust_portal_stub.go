// SPDX-License-Identifier: Apache-2.0
//go:build !enterprise

// Package main provides community-edition stubs for Trust Framework
// and SIEM wiring. The real implementations live in the enterprise
// build (build tag: enterprise) and import pkg/trust and pkg/siem.

package main

import (
	"net/http"
)

// wireTrustPortalHandlers is a community stub. In the enterprise edition,
// this function wires the trust portal HTTP endpoints (GET /trust, etc.).
func wireTrustPortalHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/trust", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","message":"trust portal (community edition)"}`))
	})
}
