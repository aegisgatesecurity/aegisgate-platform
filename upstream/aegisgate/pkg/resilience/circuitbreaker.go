// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package resilience

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	// StateClosed - normal operation, requests pass through
	StateClosed CircuitState = iota
	// StateOpen - failures exceeded threshold, requests fail fast
	StateOpen
	// StateHalfOpen - testing if service recovered
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig holds configuration for a circuit breaker
type CircuitBreakerConfig struct {
	// FailureThreshold - number of consecutive failures before opening circuit (default: 5)
	FailureThreshold int
	// SuccessThreshold - number of consecutive successes needed to close circuit from half-open (default: 3)
	SuccessThreshold int
	// Timeout - duration the circuit stays open before transitioning to half-open (default: 30s)
	Timeout time.Duration
	// RequestTimeout - timeout for each individual request (default: 10s)
	RequestTimeout time.Duration
	// MaxRequests - max requests allowed in half-open state (default: 3)
	MaxRequests int
}

// DefaultCircuitBreakerConfig returns default configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 3,
		Timeout:          30 * time.Second,
		RequestTimeout:   10 * time.Second,
		MaxRequests:      3,
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config CircuitBreakerConfig

	mu               sync.RWMutex
	state            CircuitState
	failures         int
	successes        int
	lastFailure      time.Time
	halfOpenRequests int

	// Metrics
	totalRequests    atomic.Int64
	failedRequests   atomic.Int64
	rejectedRequests atomic.Int64
	stateChanges     atomic.Int64
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 3
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.MaxRequests <= 0 {
		config.MaxRequests = 3
	}

	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

// Execute runs the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	cb.totalRequests.Add(1)

	// Check if we should allow the request
	if !cb.allowRequest() {
		cb.rejectedRequests.Add(1)
		slog.Warn("Circuit breaker open, rejecting request",
			"state", cb.state.String(),
			"timeout_remaining", cb.timeUntilHalfOpen())
		return &CircuitOpenError{
			State:      cb.state.String(),
			RetryAfter: cb.timeUntilHalfOpen(),
		}
	}

	// Create a context with timeout
	reqCtx, cancel := context.WithTimeout(ctx, cb.config.RequestTimeout)
	defer cancel()

	// Execute the function
	err := fn(reqCtx)

	// Record the result
	cb.recordResult(err)

	return err
}

// allowRequest checks if a request should be allowed
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if timeout has elapsed to transition to half-open
		if time.Since(cb.lastFailure) >= cb.config.Timeout {
			cb.transitionToHalfOpenLocked()
			return true
		}
		return false
	case StateHalfOpen:
		// Only allow limited requests in half-open state
		return cb.halfOpenRequests < cb.config.MaxRequests
	default:
		return false
	}
}

// recordResult records the result of a request
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failedRequests.Add(1)
		cb.failures++
		cb.lastFailure = time.Now()
		cb.successes = 0

		slog.Debug("Circuit breaker recorded failure",
			"failures", cb.failures,
			"threshold", cb.config.FailureThreshold,
			"state", cb.state.String())

		// Transition to open if threshold exceeded
		if cb.state == StateClosed && cb.failures >= cb.config.FailureThreshold {
			cb.transitionToOpenLocked()
		}

		// Reset half-open on failure
		if cb.state == StateHalfOpen {
			cb.transitionToOpenLocked()
		}
	} else {
		cb.successes++
		cb.failures = 0

		slog.Debug("Circuit breaker recorded success",
			"successes", cb.successes,
			"threshold", cb.config.SuccessThreshold,
			"state", cb.state.String())

		// Transition to closed if success threshold met in half-open
		if cb.state == StateHalfOpen && cb.successes >= cb.config.SuccessThreshold {
			cb.transitionToClosedLocked()
		}
	}

	// Track half-open requests
	if cb.state == StateHalfOpen {
		cb.halfOpenRequests++
	}
}

// transitionToOpenLocked transitions to open state (must hold lock)
func (cb *CircuitBreaker) transitionToOpenLocked() {
	if cb.state != StateOpen {
		cb.state = StateOpen
		cb.stateChanges.Add(1)
		slog.Warn("Circuit breaker opened",
			"failures", cb.failures,
			"threshold", cb.config.FailureThreshold)
	}
}

// transitionToHalfOpenLocked transitions to half-open state (must hold lock)
func (cb *CircuitBreaker) transitionToHalfOpenLocked() {
	cb.state = StateHalfOpen
	cb.stateChanges.Add(1)
	cb.halfOpenRequests = 0
	cb.successes = 0
	slog.Info("Circuit breaker transitioning to half-open",
		"timeout", cb.config.Timeout)
}

// transitionToClosedLocked transitions to closed state (must hold lock)
func (cb *CircuitBreaker) transitionToClosedLocked() {
	cb.state = StateClosed
	cb.stateChanges.Add(1)
	cb.failures = 0
	cb.successes = 0
	cb.halfOpenRequests = 0
	slog.Info("Circuit breaker closed")
}

// timeUntilHalfOpen returns the time until the circuit transitions to half-open
func (cb *CircuitBreaker) timeUntilHalfOpen() time.Duration {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if cb.state != StateOpen {
		return 0
	}

	elapsed := time.Since(cb.lastFailure)
	if elapsed >= cb.config.Timeout {
		return 0
	}
	return cb.config.Timeout - elapsed
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetMetrics returns current metrics
func (cb *CircuitBreaker) GetMetrics() CircuitBreakerMetrics {
	return CircuitBreakerMetrics{
		State:            cb.state.String(),
		Failures:         cb.failures,
		Successes:        cb.successes,
		TotalRequests:    cb.totalRequests.Load(),
		FailedRequests:   cb.failedRequests.Load(),
		RejectedRequests: cb.rejectedRequests.Load(),
		StateChanges:     cb.stateChanges.Load(),
		Timeout:          cb.config.Timeout,
		RequestTimeout:   cb.config.RequestTimeout,
	}
}

// GetState returns the current circuit state as a string
func (cb *CircuitBreaker) GetState() string {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state.String()
}

// TotalRequests returns the total number of requests
func (cb *CircuitBreaker) TotalRequests() int64 {
	return cb.totalRequests.Load()
}

// FailedRequests returns the number of failed requests
func (cb *CircuitBreaker) FailedRequests() int64 {
	return cb.failedRequests.Load()
}

// RejectedRequests returns the number of rejected requests
func (cb *CircuitBreaker) RejectedRequests() int64 {
	return cb.rejectedRequests.Load()
}

// StateChanges returns the number of state changes
func (cb *CircuitBreaker) StateChanges() int64 {
	return cb.stateChanges.Load()
}

// CircuitBreakerMetrics holds circuit breaker metrics
type CircuitBreakerMetrics struct {
	State            string
	Failures         int
	Successes        int
	TotalRequests    int64
	FailedRequests   int64
	RejectedRequests int64
	StateChanges     int64
	Timeout          time.Duration
	RequestTimeout   time.Duration
}

// CircuitOpenError is returned when the circuit is open
type CircuitOpenError struct {
	State      string
	RetryAfter time.Duration
}

func (e *CircuitOpenError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("circuit breaker is %s, retry after %v", e.State, e.RetryAfter)
	}
	return fmt.Sprintf("circuit breaker is %s", e.State)
}

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	// MaxAttempts - maximum number of retry attempts (default: 3)
	MaxAttempts int
	// InitialDelay - initial delay between retries (default: 100ms)
	InitialDelay time.Duration
	// MaxDelay - maximum delay between retries (default: 30s)
	MaxDelay time.Duration
	// Multiplier - exponential backoff multiplier (default: 2.0)
	Multiplier float64
	// Jitter - whether to add jitter to delays (default: true)
	Jitter bool
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// RetryExecutor executes functions with retry logic
type RetryExecutor struct {
	config RetryConfig
}

// NewRetryExecutor creates a new retry executor
func NewRetryExecutor(config RetryConfig) *RetryExecutor {
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 3
	}
	if config.InitialDelay <= 0 {
		config.InitialDelay = 100 * time.Millisecond
	}
	if config.MaxDelay <= 0 {
		config.MaxDelay = 30 * time.Second
	}
	if config.Multiplier <= 0 {
		config.Multiplier = 2.0
	}

	return &RetryExecutor{
		config: config,
	}
}

// Execute executes the function with retry logic
func (r *RetryExecutor) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	var lastErr error
	delay := r.config.InitialDelay

	for attempt := 1; attempt <= r.config.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		slog.Debug("Retry attempt",
			"attempt", attempt,
			"max_attempts", r.config.MaxAttempts)

		if err := fn(ctx); err != nil {
			lastErr = err

			// Don't retry on context cancellation
			if ctx.Err() != nil {
				return err
			}

			// Last attempt - return error
			if attempt == r.config.MaxAttempts {
				slog.Error("Retry exhausted",
					"attempts", attempt,
					"error", err)
				return err
			}

			// Calculate delay with exponential backoff
			sleepDuration := delay
			if r.config.Jitter {
				sleepDuration = addJitter(sleepDuration)
			}

			slog.Warn("Retry attempt failed, waiting before next attempt",
				"attempt", attempt,
				"error", err,
				"delay", sleepDuration)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleepDuration):
			}

			// Apply exponential backoff
			delay = time.Duration(float64(delay) * r.config.Multiplier)
			if delay > r.config.MaxDelay {
				delay = r.config.MaxDelay
			}
		} else {
			// Success
			if attempt > 1 {
				slog.Info("Retry succeeded",
					"attempts", attempt)
			}
			return nil
		}
	}

	return lastErr
}

// addJitter adds random jitter to the duration
func addJitter(d time.Duration) time.Duration {
	// 25% jitter
	jitter := d / 4
	if jitter < 1 {
		jitter = 1
	}
	// This is a simple deterministic jitter for now
	// In production, consider using rand.Int63n
	return d + jitter/2
}

// TimeoutExecutor executes functions with timeout
type TimeoutExecutor struct {
	DefaultTimeout time.Duration
}

// NewTimeoutExecutor creates a new timeout executor
func NewTimeoutExecutor(timeout time.Duration) *TimeoutExecutor {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &TimeoutExecutor{
		DefaultTimeout: timeout,
	}
}

// Execute executes the function with timeout
func (t *TimeoutExecutor) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	// Use the context's timeout if it has one, otherwise use default
	timeout := t.DefaultTimeout
	if ctx.Done() != nil {
		select {
		case <-ctx.Done():
			// Context already cancelled
			return ctx.Err()
		default:
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return fn(ctx)
}

// ResilientClient wraps HTTP operations with circuit breaker and retry logic
type ResilientClient struct {
	CircuitBreaker  *CircuitBreaker
	RetryExecutor   *RetryExecutor
	TimeoutExecutor *TimeoutExecutor
}

// ResilientClientConfig holds configuration for a resilient client
type ResilientClientConfig struct {
	CircuitBreaker CircuitBreakerConfig
	Retry          RetryConfig
	Timeout        time.Duration
}

// NewResilientClient creates a new resilient client
func NewResilientClient(config ResilientClientConfig) *ResilientClient {
	return &ResilientClient{
		CircuitBreaker:  NewCircuitBreaker(config.CircuitBreaker),
		RetryExecutor:   NewRetryExecutor(config.Retry),
		TimeoutExecutor: NewTimeoutExecutor(config.Timeout),
	}
}

// ExecuteWithResilience executes a function with circuit breaker, retry, and timeout
func (rc *ResilientClient) ExecuteWithResilience(ctx context.Context, fn func(ctx context.Context) error) error {
	// Wrap with circuit breaker - this handles the timeout per request
	return rc.CircuitBreaker.Execute(ctx, func(cbCtx context.Context) error {
		// Wrap with retry logic
		return rc.RetryExecutor.Execute(cbCtx, fn)
	})
}

// GetMetrics returns combined metrics
func (rc *ResilientClient) GetMetrics() map[string]interface{} {
	cbMetrics := rc.CircuitBreaker.GetMetrics()
	return map[string]interface{}{
		"circuit_breaker": cbMetrics,
		"timeout":         rc.TimeoutExecutor.DefaultTimeout,
	}
}
