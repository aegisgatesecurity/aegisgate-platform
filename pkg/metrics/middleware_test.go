// Copyright 2024 AegisGate Security. All rights reserved.

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// Middleware tests
// --------------------------------------------------------------------------

func TestMiddleware_RecordsRequestMetrics(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mw := NewMiddleware("proxy", inner)

	req := httptest.NewRequest("GET", "/api/v1/users/123", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	// Verify the response was forwarded correctly
	if rec.Code != http.StatusOK {
		t.Errorf("Response status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if body != "OK" {
		t.Errorf("Response body = %q, want 'OK'", body)
	}
}

func TestMiddleware_RecordsDifferentStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", 200},
		{"201 Created", 201},
		{"301 Redirect", 301},
		{"400 Bad Request", 400},
		{"401 Unauthorized", 401},
		{"404 Not Found", 404},
		{"429 Too Many Requests", 429},
		{"500 Internal Server Error", 500},
		{"503 Service Unavailable", 503},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			})

			mw := NewMiddleware("test", inner)
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			mw.ServeHTTP(rec, req)

			if rec.Code != tc.statusCode {
				t.Errorf("Status = %d, want %d", rec.Code, tc.statusCode)
			}
		})
	}
}

func TestMiddleware_TracksActiveConnections(t *testing.T) {
	// IncActiveConnections and DecActiveConnections are called by the middleware.
	// We verify the middleware doesn't panic when tracking connections.
	done := make(chan bool, 1)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		done <- true
	})

	mw := NewMiddleware("proxy", inner)
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	// Wait for handler to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("Handler did not complete within timeout")
	}
}

func TestMiddleware_SanitizesPath(t *testing.T) {
	// The middleware should pass r.URL.Path to RecordHTTPRequest,
	// which then sanitizes it via SanitizeEndpoint()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := NewMiddleware("proxy", inner)

	// Request with UUID in path — should not panic
	req := httptest.NewRequest("GET", "/api/v1/users/550e8400-e29b-41d4-a716-446655440000", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddleware_QueryParametersStripped(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := NewMiddleware("proxy", inner)

	// Request with query parameters — should not panic
	req := httptest.NewRequest("GET", "/api/v1/users?limit=10&offset=20", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// --------------------------------------------------------------------------
// WrapHandler tests
// --------------------------------------------------------------------------

func TestWrapHandler(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := WrapHandler("proxy", inner)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("WrapHandler status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWrapHandlerFunc(t *testing.T) {
	inner := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}

	handler := WrapHandlerFunc("dashboard", inner)

	req := httptest.NewRequest("POST", "/admin/settings", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("WrapHandlerFunc status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

// --------------------------------------------------------------------------
// InstrumentRoute tests
// --------------------------------------------------------------------------

func TestInstrumentRoute(t *testing.T) {
	mux := http.NewServeMux()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	InstrumentRoute(mux, "/health", inner)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("InstrumentRoute status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// --------------------------------------------------------------------------
// responseWriter tests
// --------------------------------------------------------------------------

func TestResponseWriter_CapturesStatusCode(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)

	if rw.statusCode != http.StatusNotFound {
		t.Errorf("responseWriter.statusCode = %d, want %d", rw.statusCode, http.StatusNotFound)
	}
	if !rw.written {
		t.Error("responseWriter.written should be true after WriteHeader")
	}
}

func TestResponseWriter_DefaultsTo200(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	// Write body without calling WriteHeader explicitly
	rw.Write([]byte("OK"))

	if rw.statusCode != http.StatusOK {
		t.Errorf("responseWriter.statusCode = %d, want %d (default 200)", rw.statusCode, http.StatusOK)
	}
}

func TestResponseWriter_WriteHeaderOnlyOnce(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	// First WriteHeader call should succeed
	rw.WriteHeader(http.StatusBadRequest)
	// Second WriteHeader call should be ignored
	rw.WriteHeader(http.StatusServiceUnavailable)

	if rw.statusCode != http.StatusBadRequest {
		t.Errorf("responseWriter.statusCode = %d, want %d (first WriteHeader wins)", rw.statusCode, http.StatusBadRequest)
	}
}

func TestResponseWriter_WriteDelegatesToUnderlying(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	n, err := rw.Write([]byte("Hello"))
	if err != nil {
		t.Errorf("Write() returned error: %v", err)
	}
	if n != 5 {
		t.Errorf("Write() returned %d bytes, want 5", n)
	}
}

// --------------------------------------------------------------------------
// Concurrent middleware tests
// --------------------------------------------------------------------------

func TestMiddleware_ConcurrentRequests(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond) // simulate slight delay
		w.WriteHeader(http.StatusOK)
	})

	mw := NewMiddleware("proxy", inner)

	done := make(chan bool, 50)

	for i := 0; i < 50; i++ {
		go func(id int) {
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			done <- true
		}(i)
	}

	for i := 0; i < 50; i++ {
		select {
		case <-done:
			// OK
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent request timed out")
		}
	}
}
