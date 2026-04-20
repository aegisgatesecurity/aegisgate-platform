// SPDX-License-Identifier: Apache-2.0
// =========================================================================

// =========================================================================
//
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
