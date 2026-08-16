// SPDX-License-Identifier: Apache-2.0
//go:build !enterprise

// Package main provides the community-edition Trust Framework HTTP handler.
//
// The Trust Framework (trust scoring, attestation, pillar-based governance)
// is an enterprise-tier feature. In the community edition, the /trust
// endpoint returns a JSON response indicating the feature requires an
// enterprise license, with a 200 status code so monitoring doesn't flag
// it as an error.
//
// The enterprise build (cmd/aegisgate-platform/trust_portal.go,
// build tag: enterprise) provides the full implementation with trust
// scoring, pillar dashboards, and attestation endpoints.

package main

import (
	"encoding/json"
	"net/http"
)

// wireTrustPortalHandlers registers the Trust Framework HTTP endpoints.
// In the community edition, /trust returns a JSON message indicating
// the feature requires an enterprise license.
func wireTrustPortalHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/trust", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "enterprise_required",
			"message": "Trust Framework requires enterprise license — see https://aegisgate.dev/pricing for details",
		})
	})
}
