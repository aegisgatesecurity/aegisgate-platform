package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRejectDangerousMethods(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rejectDangerousMethods(inner)

	tests := []struct {
		method         string
		expectedStatus int
	}{
		{http.MethodGet, http.StatusOK},
		{http.MethodPost, http.StatusOK},
		{http.MethodPut, http.StatusOK},
		{http.MethodDelete, http.StatusOK},
		{http.MethodPatch, http.StatusOK},
		{http.MethodOptions, http.StatusOK},
		{http.MethodTrace, http.StatusMethodNotAllowed},
		{"TRACK", http.StatusMethodNotAllowed},
		{http.MethodConnect, http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/test", nil)
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.expectedStatus {
				t.Errorf("method %s: expected %d, got %d", tt.method, tt.expectedStatus, rec.Code)
			}
		})
	}
}
