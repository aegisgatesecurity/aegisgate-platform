// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package plugin provides the plugin hook system for AegisGate extensibility.
package plugin

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// RequestContext holds the request data passed to plugin hooks
type RequestContext struct {
	// Request is the HTTP request (may be modified by plugins)
	Request *http.Request
	// ResponseWriter is the response (plugins can write to it)
	ResponseWriter http.ResponseWriter
	// Body is the request body (for request hooks)
	Body []byte
	// Upstream is the target upstream URL
	Upstream string
	// ClientIP is the client's IP address
	ClientIP string
	// Protocol is the protocol used (HTTP/1.1, HTTP/2, HTTP/3)
	Protocol string
	// TLSInfo contains TLS connection details
	TLSInfo *TLSInfo
	// Metadata is additional context metadata
	Metadata map[string]interface{}
	// Timestamp when the request was received
	Timestamp time.Time
}

// TLSInfo contains TLS connection information
type TLSInfo struct {
	Version     string
	CipherSuite string
	ServerName  string
	Verified    bool
	// For mTLS - client certificate info
	ClientCert *ClientCertInfo
}

// ClientCertInfo contains client certificate information
type ClientCertInfo struct {
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	Serial    string
}

// ResponseContext holds the response data passed to plugin hooks
type ResponseContext struct {
	// StatusCode is the HTTP status code
	StatusCode int
	// Status is the HTTP status string
	Status string
	// Headers are the response headers
	Headers http.Header
	// Body is the response body
	Body []byte
	// Latency is the time taken to get the response from upstream
	Latency time.Duration
	// Error contains any error that occurred
	Error error
	// Metadata is additional context metadata
	Metadata map[string]interface{}
}

// ConnectionContext holds connection-level information
type ConnectionContext struct {
	// LocalAddr is the local address
	LocalAddr string
	// RemoteAddr is the remote client address
	RemoteAddr string
	// RemotePort is the remote client port
	RemotePort int
	// LocalPort is the local server port
	LocalPort int
	// IsEncrypted indicates if the connection is TLS encrypted
	IsEncrypted bool
	// ConnectionID is a unique identifier for this connection
	ConnectionID string
	// Metadata is additional context metadata
	Metadata map[string]interface{}
}

// ErrorContext holds error information passed to error hooks
type ErrorContext struct {
	// Error is the actual error
	Error error
	// Hook is the hook type where the error occurred
	Hook HookType
	// Request is the associated request (if available)
	Request *http.Request
	// ConnectionID is the connection where error occurred
	ConnectionID string
	// Timestamp when the error occurred
	Timestamp time.Time
	// Metadata is additional context metadata
	Metadata map[string]interface{}
}

// PeriodicContext holds context for periodic hook execution
type PeriodicContext struct {
	// Timestamp is when the hook is being executed
	Timestamp time.Time
	// Interval is the configured interval
	Interval time.Duration
	// Metadata is additional context metadata
	Metadata map[string]interface{}
}

// HookResult represents the result of a plugin hook execution
type HookResult struct {
	// Continue indicates whether to continue to the next plugin/hook
	Continue bool
	// Stop indicates whether to stop the entire pipeline
	Stop bool
	// Error contains any error that occurred
	Error error
	// ModifiedRequest is a modified request (for request hooks)
	ModifiedRequest *http.Request
	// ModifiedBody is a modified body (for body-processing hooks)
	ModifiedBody []byte
	// Metadata is additional data to pass to subsequent hooks
	Metadata map[string]interface{}
	// ResponseHeaders headers to add/modify
	ResponseHeaders http.Header
	// StatusCode to set (for response hooks)
	StatusCode int
}

// DefaultHookResult returns a default successful hook result
func DefaultHookResult() HookResult {
	return HookResult{
		Continue: true,
		Stop:     false,
		Metadata: make(map[string]interface{}),
	}
}

// ErrorHookResult returns a hook result indicating an error
func ErrorHookResult(err error) HookResult {
	return HookResult{
		Continue: false,
		Stop:     true,
		Error:    err,
		Metadata: make(map[string]interface{}),
	}
}

// StopHookResult returns a hook result that stops the pipeline
func StopHookResult() HookResult {
	return HookResult{
		Continue: false,
		Stop:     true,
		Metadata: make(map[string]interface{}),
	}
}

// RequestProcessor is implemented by plugins that process requests
type RequestProcessor interface {
	// ProcessRequest is called for request hooks
	ProcessRequest(ctx context.Context, reqCtx *RequestContext) (*HookResult, error)
}

// ResponseProcessor is implemented by plugins that process responses
type ResponseProcessor interface {
	// ProcessResponse is called for response hooks
	ProcessResponse(ctx context.Context, reqCtx *RequestContext, respCtx *ResponseContext) (*HookResult, error)
}

// ConnectionHandler is implemented by plugins that handle connection events
type ConnectionHandler interface {
	// OnConnectionOpen is called when a connection opens
	OnConnectionOpen(ctx context.Context, connCtx *ConnectionContext) error
	// OnConnectionClose is called when a connection closes
	OnConnectionClose(ctx context.Context, connCtx *ConnectionContext) error
}

// ErrorHandler is implemented by plugins that handle errors
type ErrorHandler interface {
	// OnError is called when an error occurs
	OnError(ctx context.Context, errCtx *ErrorContext) error
}

// PeriodicTask is implemented by plugins that run periodic tasks
type PeriodicTask interface {
	// OnPeriodic is called at regular intervals
	OnPeriodic(ctx context.Context, periodicCtx *PeriodicContext) error
	// Interval returns the interval at which OnPeriodic should be called
	Interval() time.Duration
}

// FilterPlugin is a convenience type for filter plugins
type FilterPlugin interface {
	Plugin
	RequestProcessor
	ResponseProcessor
}

// NewRequestContext creates a new RequestContext
func NewRequestContext(r *http.Request, rw http.ResponseWriter, upstream string) *RequestContext {
	clientIP := ""
	proto := ""

	if r != nil {
		clientIP = r.RemoteAddr
		proto = r.Proto
	}

	return &RequestContext{
		Request:        r,
		ResponseWriter: rw,
		Upstream:       upstream,
		ClientIP:       clientIP,
		Protocol:       proto,
		Metadata:       make(map[string]interface{}),
		Timestamp:      time.Now(),
	}
}

// NewResponseContext creates a new ResponseContext
func NewResponseContext(statusCode int, headers http.Header, body []byte, latency time.Duration) *ResponseContext {
	return &ResponseContext{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
		Latency:    latency,
		Metadata:   make(map[string]interface{}),
	}
}

// NewConnectionContext creates a new ConnectionContext
func NewConnectionContext(localAddr, remoteAddr string, isEncrypted bool) *ConnectionContext {
	return &ConnectionContext{
		LocalAddr:    localAddr,
		RemoteAddr:   remoteAddr,
		IsEncrypted:  isEncrypted,
		Metadata:     make(map[string]interface{}),
		ConnectionID: fmt.Sprintf("%s-%d", remoteAddr, time.Now().UnixNano()),
	}
}

// NewErrorContext creates a new ErrorContext
func NewErrorContext(err error, hook HookType, req *http.Request, connID string) *ErrorContext {
	return &ErrorContext{
		Error:        err,
		Hook:         hook,
		Request:      req,
		ConnectionID: connID,
		Timestamp:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}
}
