// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform Go SDK — HTTP Client
// =========================================================================
//
// client_http.go provides the HTTPClient wrapper with retry logic, error
// handling, and JSON marshalling/unmarshalling for all SDK requests.
// =========================================================================

package aegisgate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrorResponse represents a standard AegisGate API error payload.
type APIError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	Err        string `json:"error"`
}

// Error implements the error interface for ErrorResponse.
func (e *APIError) Error() string {
	return fmt.Sprintf("aegisgate: %s (status %d): %s", e.Err, e.StatusCode, e.Message)
}

// HTTPClient wraps the underlying *http.Client and adds retry + JSON handling.
type HTTPClient struct {
	client *Client
}

// Do executes an HTTP request with retries and JSON decoding.
func (hc *HTTPClient) Do(ctx context.Context, method, url string, body, v interface{}) error {
	var bodyBytes []byte
	var err error

	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("aegisgate: failed to marshal request body: %w", err)
		}
	}

	maxRetries := hc.client.cfg.MaxRetries
	if maxRetries < 1 {
		maxRetries = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffDuration(attempt)):
			}
		}

		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return fmt.Errorf("aegisgate: failed to create request: %w", err)
		}

		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		hc.client.setAuthHeaders(req)

		resp, err := hc.client.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("aegisgate: request failed: %w", err)
			continue // retry on network errors
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("aegisgate: failed to read response body: %w", err)
			continue
		}

		if resp.StatusCode >= 500 {
			lastErr = &ErrorResponse{
				StatusCode: resp.StatusCode,
				Message:    string(respBody),
				Error:      http.StatusText(resp.StatusCode),
			}
			continue // retry on server errors
		}

		if resp.StatusCode >= 400 {
			errResp := &APIError{StatusCode: resp.StatusCode}
			if jsonErr := json.Unmarshal(respBody, errResp); jsonErr != nil {
				errResp.Message = string(respBody)
				errResp.Err = http.StatusText(resp.StatusCode)
			}
			return errResp
		}

		if v != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, v); err != nil {
				return fmt.Errorf("aegisgate: failed to decode response: %w", err)
			}
		}

		return nil
	}

	return lastErr
}

// Get is a convenience wrapper for GET requests.
func (hc *HTTPClient) Get(ctx context.Context, url string, v interface{}) error {
	return hc.Do(ctx, http.MethodGet, url, nil, v)
}

// Post is a convenience wrapper for POST requests.
func (hc *HTTPClient) Post(ctx context.Context, url string, body, v interface{}) error {
	return hc.Do(ctx, http.MethodPost, url, body, v)
}

// Put is a convenience wrapper for PUT requests.
func (hc *HTTPClient) Put(ctx context.Context, url string, body, v interface{}) error {
	return hc.Do(ctx, http.MethodPut, url, body, v)
}

// Delete is a convenience wrapper for DELETE requests.
func (hc *HTTPClient) Delete(ctx context.Context, url string, v interface{}) error {
	return hc.Do(ctx, http.MethodDelete, url, nil, v)
}

// backoffDuration returns an exponential backoff duration for the given
// attempt number (0-indexed). Uses 500ms, 1s, 2s, 4s, ...
func backoffDuration(attempt int) time.Duration {
	ms := 500 * (1 << attempt)
	if ms > 8000 {
		ms = 8000
	}
	return time.Duration(ms) * time.Millisecond
}