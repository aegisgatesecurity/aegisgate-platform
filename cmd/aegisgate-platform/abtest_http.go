// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — A/B Testing HTTP Endpoints (v4.3.1)
//
// abtest_http.go provides HTTP endpoints for ML model A/B testing:
//   POST   /api/v1/abtest/tests          — create a new test
//   GET    /api/v1/abtest/tests          — list all tests
//   POST   /api/v1/abtest/tests/{id}/start  — start a test
//   POST   /api/v1/abtest/tests/{id}/stop   — stop a test
//   GET    /api/v1/abtest/tests/{id}/metrics — get test metrics
//   POST   /api/v1/abtest/tests/{id}/assign  — assign a request to a variant
//   POST   /api/v1/abtest/tests/{id}/result  — record a result
//
// All endpoints require admin permission.

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/abtest"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
)

type abtestService = abtest.Service

func wireABTestHandlers(mux *http.ServeMux, amw *auth.Middleware, svc *abtestService) {
	if svc == nil {
		return
	}

	// POST/GET /api/v1/abtest/tests
	mux.HandleFunc("/api/v1/abtest/tests", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			amw.AdminOnly(svcCreateTestHandler(svc))(w, r)
		case http.MethodGet:
			amw.AdminOnly(svcListTestsHandler(svc))(w, r)
		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	// /api/v1/abtest/tests/{id}/...
	mux.HandleFunc("/api/v1/abtest/tests/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/abtest/tests/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) < 2 {
			http.NotFound(w, r)
			return
		}
		testID := parts[0]
		action := parts[1]

		switch action {
		case "start":
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			amw.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
				if err := svc.StartTest(r.Context(), testID); err != nil {
					writeJSONError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeJSON(w, map[string]string{"status": "started", "test_id": testID})
			})(w, r)

		case "stop":
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			amw.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
				if err := svc.StopTest(r.Context(), testID); err != nil {
					writeJSONError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeJSON(w, map[string]string{"status": "stopped", "test_id": testID})
			})(w, r)

		case "metrics":
			if r.Method != http.MethodGet {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			amw.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
				metrics, err := svc.GetMetrics(r.Context(), testID)
				if err != nil {
					writeJSONError(w, http.StatusNotFound, err.Error())
					return
				}
				writeJSON(w, metrics)
			})(w, r)

		case "assign":
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			amw.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					RequestID string `json:"request_id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					writeJSONError(w, http.StatusBadRequest, "invalid request body")
					return
				}
				if req.RequestID == "" {
					writeJSONError(w, http.StatusBadRequest, "request_id is required")
					return
				}
				variant, err := svc.AssignVariant(r.Context(), testID, req.RequestID)
				if err != nil {
					writeJSONError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeJSON(w, map[string]string{"variant": variant, "test_id": testID})
			})(w, r)

		case "result":
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			amw.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					VariantName   string  `json:"variant_name"`
					Detected      bool    `json:"detected"`
					FalsePositive bool    `json:"false_positive"`
					LatencyMs     float64 `json:"latency_ms"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					writeJSONError(w, http.StatusBadRequest, "invalid request body")
					return
				}
				svc.RecordResult(r.Context(), testID, req.VariantName, req.Detected, req.FalsePositive, req.LatencyMs)
				writeJSON(w, map[string]string{"status": "recorded"})
			})(w, r)

		default:
			http.NotFound(w, r)
		}
	})
}

func svcCreateTestHandler(svc *abtestService) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Variants    []abtest.Variant `json:"variants"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Name == "" {
			writeJSONError(w, http.StatusBadRequest, "name is required")
			return
		}
		if len(req.Variants) < 2 {
			writeJSONError(w, http.StatusBadRequest, "at least 2 variants are required")
			return
		}

		test, err := svc.CreateTest(r.Context(), req.Name, req.Description, req.Variants)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(test)
	}
}

func svcListTestsHandler(svc *abtestService) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tests := svc.ListTests(r.Context())
		if tests == nil {
			tests = []*abtest.Test{}
		}
		writeJSON(w, map[string]interface{}{
			"tests": tests,
			"count": len(tests),
			"time":  time.Now().UTC(),
		})
	}
}
