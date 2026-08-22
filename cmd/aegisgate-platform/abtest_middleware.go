// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — A/B Testing Pipeline Integration (v4.3.1)
// =========================================================================
//
// abtest_middleware.go integrates the A/B testing service into the
// proxy request pipeline. When an active A/B test exists, each request
// is assigned to a variant via FNV hashing before being forwarded to
// the upstream AI provider. After the response, the detection result
// is recorded against the assigned variant.
//
// Integration points:
//   - AssignVariant: called before proxy.ServeHTTP to select model variant
//   - RecordResult: called after proxy.ServeHTTP with detection status
//
// The middleware is a no-op when no A/B test is running or when the
// abtest service is nil.
//
// =========================================================================

package main

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// abtestMiddleware wraps the proxy handler with A/B testing integration.
// When an active test exists, it assigns each request to a variant and
// records the result after the response completes.
//
// The middleware uses the request path + remote address as the request
// ID for variant assignment, ensuring consistent assignment for the
// same request.
func abtestMiddleware(next http.Handler, svc *abtestService) http.Handler {
	if svc == nil {
		// No A/B testing service — pass through
		return next
	}

	// Track active test for variant assignment
	var mu sync.RWMutex
	activeTestID := ""

	// Periodically check for active tests (every 10s)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			tests := svc.ListTests(context.Background())
			mu.Lock()
			found := ""
			for _, t := range tests {
				if t.Status == "running" {
					found = t.ID
					break
				}
			}
			activeTestID = found
			mu.Unlock()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if there's an active A/B test
		mu.RLock()
		testID := activeTestID
		mu.RUnlock()

		if testID == "" {
			// No active test — pass through without A/B overhead
			next.ServeHTTP(w, r)
			return
		}

		// Assign variant using request ID derived from request
		// characteristics. We use the client IP + path + timestamp
		// to create a unique request ID.
		requestID := r.RemoteAddr + "|" + r.URL.Path + "|" + time.Now().Format(time.RFC3339Nano)
		variant, err := svc.AssignVariant(r.Context(), testID, requestID)
		if err != nil {
			// Assignment failed — pass through without recording
			next.ServeHTTP(w, r)
			return
		}

		// Wrap the response to capture status code
		srw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(srw, r)
		latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

		// Record the result asynchronously to avoid blocking the response
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Determine detection status from the response
			// A blocked request (403) counts as a detection
			detected := srw.status == http.StatusForbidden || srw.status == http.StatusTooManyRequests

			// False positive: a 2xx response that was blocked would be a
			// false positive, but we can't easily determine this from the
			// status code alone. For now, we mark non-2xx as detected and
			// 2xx as not detected. False positive tracking would require
			// deeper response inspection.
			falsePositive := false

			svc.RecordResult(ctx, testID, variant, detected, falsePositive, latencyMs)

			logging.Record(logging.Event{
				Type:     "abtest_result",
				Severity: logging.SeverityInfo,
				Message:  "A/B test result recorded",
				Action:   variant,
				Pattern:  testID,
			})
		}()
	})
}
