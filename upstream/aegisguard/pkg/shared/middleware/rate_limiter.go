// SPDX-License-Identifier: MIT
// =========================================================================
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// =========================================================================

package middleware

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig holds rate limiting configuration for agents
type RateLimitConfig struct {
	RequestsPerMinute int
	Burst             int
	BlockDuration     time.Duration
	KeyFunc           func(r *http.Request) string
}

// DefaultRateLimitConfig returns default rate limit configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 1000,
		Burst:             100,
		BlockDuration:     time.Minute * 5,
		KeyFunc:           DefaultKeyFunc,
	}
}

// getRealClientIP extracts the real client IP from request
func getRealClientIP(r *http.Request) string {
	// Priority 1: Cloudflare
	if cfIP := r.Header.Get("cf-connecting-ip"); cfIP != "" {
		return cfIP
	}

	// Priority 2: X-Forwarded-For (only from private IPs)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		firstIP := strings.Split(forwarded, ",")[0]
		firstIP = strings.TrimSpace(firstIP)
		if isValidIP(firstIP) && isPrivateIP(firstIP) {
			return firstIP
		}
	}

	// Fallback: RemoteAddr
	remoteAddr := r.RemoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		remoteAddr = remoteAddr[:idx]
	}
	return remoteAddr
}

// isValidIP checks if string is a valid IP address
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// isPrivateIP checks if IP is a private/internal network address
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	if strings.HasPrefix(ip, "10.") {
		return true
	}
	if strings.HasPrefix(ip, "192.168.") {
		return true
	}
	if strings.HasPrefix(ip, "127.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			secondOctet, err := strconv.Atoi(parts[1])
			if err == nil && secondOctet >= 16 && secondOctet <= 31 {
				return true
			}
		}
	}
	if strings.HasPrefix(ip, "fe80::") || strings.HasPrefix(ip, "fc") || strings.HasPrefix(ip, "fd") {
		return true
	}
	if ip == "::1" {
		return true
	}

	return false
}

// DefaultKeyFunc generates a rate limit key from the request
func DefaultKeyFunc(r *http.Request) string {
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "api:" + apiKey
	}
	if agentID := r.Header.Get("X-Agent-ID"); agentID != "" {
		return "agent:" + agentID
	}
	return "ip:" + getRealClientIP(r)
}

// RateLimiter implements per-client rate limiting using token bucket
type RateLimiter struct {
	mu          sync.Mutex
	clients     map[string]*clientLimiter
	config      RateLimitConfig
	cleanupChan chan struct{}
}

// clientLimiter holds rate limit state for a single client
type clientLimiter struct {
	tokens   float64
	lastFill time.Time
	blocked  time.Time
	burst    int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		clients:     make(map[string]*clientLimiter),
		config:      config,
		cleanupChan: make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// cleanupLoop periodically removes old entries
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.cleanupChan:
			return
		}
	}
}

// cleanup removes entries that haven't been accessed recently
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	threshold := time.Now().Add(-time.Hour)
	for key, client := range rl.clients {
		if client.lastFill.Before(threshold) {
			delete(rl.clients, key)
		}
	}
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow(key string) (allow bool, remain int, retryIn time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	client, exists := rl.clients[key]

	if !exists {
		client = &clientLimiter{
			tokens:   float64(rl.config.Burst),
			lastFill: now,
			burst:    rl.config.Burst,
		}
		rl.clients[key] = client
		return true, rl.config.Burst - 1, 0
	}

	// Check if blocked
	if !client.blocked.IsZero() && now.Before(client.blocked) {
		retryIn = client.blocked.Sub(now)
		return false, 0, retryIn
	}

	// Refill tokens
	elapsed := now.Sub(client.lastFill).Seconds()
	refill := float64(rl.config.RequestsPerMinute) * elapsed / 60.0
	client.tokens = math.Min(float64(client.burst), client.tokens+refill)
	client.lastFill = now

	// Check if allowed
	if client.tokens >= 1 {
		client.tokens--
		remain = int(client.tokens)
		return true, remain, 0
	}

	// Block the client
	client.blocked = now.Add(rl.config.BlockDuration)
	return false, 0, rl.config.BlockDuration
}

// Middleware returns a middleware that applies rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := rl.config.KeyFunc(r)
		isAllowed, remaining, retryAfter := rl.Allow(key)

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.config.RequestsPerMinute))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

		if !isAllowed {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AgentRateLimiter provides per-agent rate limiting
type AgentRateLimiter struct {
	agentLimits  map[string]*RateLimiter
	defaultLimit *RateLimiter
	mu           sync.RWMutex
}

// NewAgentRateLimiter creates a new agent-aware rate limiter
func NewAgentRateLimiter() *AgentRateLimiter {
	return &AgentRateLimiter{
		agentLimits:  make(map[string]*RateLimiter),
		defaultLimit: NewRateLimiter(DefaultRateLimitConfig()),
	}
}

// GetLimiterForAgent returns the rate limiter for a specific agent
func (arl *AgentRateLimiter) GetLimiterForAgent(agentID string) *RateLimiter {
	arl.mu.RLock()
	limiter, exists := arl.agentLimits[agentID]
	arl.mu.RUnlock()

	if exists {
		return limiter
	}

	// Create a new limiter for this agent
	arl.mu.Lock()
	defer arl.mu.Unlock()

	if limiter, exists = arl.agentLimits[agentID]; exists {
		return limiter
	}

	config := DefaultRateLimitConfig()
	limiter = NewRateLimiter(config)
	arl.agentLimits[agentID] = limiter
	return limiter
}

// AllowForAgent checks rate limit for a specific agent
func (arl *AgentRateLimiter) AllowForAgent(agentID, sessionID string) (bool, int, time.Duration) {
	limiter := arl.GetLimiterForAgent(agentID)
	key := "session:" + sessionID
	return limiter.Allow(key)
}
