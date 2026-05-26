// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Guard Errors
// =========================================================================

package acp

import "errors"

// ACP Guard errors
var (
	// Message validation errors
	ErrNilMessage       = errors.New("acp: message is nil")
	ErrInvalidMessage   = errors.New("acp: invalid message format")
	ErrInvalidMethod    = errors.New("acp: method is required")
	ErrMethodBlocked    = errors.New("acp: method is blocked")
	ErrInvalidParams    = errors.New("acp: invalid message parameters")
	ErrInvalidMessageID = errors.New("acp: invalid message ID")

	// Authentication errors
	ErrAuthenticationFailed = errors.New("acp: authentication failed")
	ErrInvalidToken         = errors.New("acp: invalid authentication token")
	ErrTokenExpired         = errors.New("acp: authentication token expired")
	ErrHMACVerification     = errors.New("acp: HMAC verification failed")
	ErrIntegrityViolation   = errors.New("acp: message integrity violation")

	// Authorization errors
	ErrUnauthorized      = errors.New("acp: unauthorized access")
	ErrCapabilityDenied  = errors.New("acp: capability denied")
	ErrInsufficientScope = errors.New("acp: insufficient scope for operation")
	ErrForbidden         = errors.New("acp: operation forbidden")

	// Rate limiting
	ErrRateLimited = errors.New("acp: rate limit exceeded")

	// Scanning errors
	ErrScanTimeout    = errors.New("acp: scan timeout")
	ErrScanFailed     = errors.New("acp: scan failed")
	ErrContentBlocked = errors.New("acp: content blocked by scanner")

	// Transport errors
	ErrTransportError   = errors.New("acp: transport error")
	ErrConnectionClosed = errors.New("acp: connection closed")
	ErrWriteFailed      = errors.New("acp: write to transport failed")
	ErrReadFailed       = errors.New("acp: read from transport failed")
)
