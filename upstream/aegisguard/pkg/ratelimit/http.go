// SPDX-FileCopyrightText: Copyright (C) 2025 AegisGuard Security
// SPDX-License-Identifier: MIT

// Package ratelimit - Rate limiting for AI agent operations
// This file provides HTTP middleware integration with proxy-aware IP extraction

package ratelimit

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// HTTP Middleware Integration
// ============================================================================

// HTTPLimiterConfig holds configuration for HTTP rate limiting middleware
type HTTPLimiterConfig struct {
	// RequestsPerMinute defines the maximum requests per minute per client
	RequestsPerMinute int
	// BurstSize defines the maximum burst capacity
	BurstSize int
	// BlockDuration defines how long a client is blocked after exceeding limits
	BlockDuration time.Duration
	// KeyFunc extracts the rate limit key from the request
	KeyFunc func(r *http.Request) string
}

// DefaultHTTPLimiterConfig returns sensible defaults for HTTP rate limiting
func DefaultHTTPLimiterConfig() HTTPLimiterConfig {
	return HTTPLimiterConfig{
		RequestsPerMinute: 60,
		BurstSize:         30,
		BlockDuration:     5 * time.Minute,
		KeyFunc:           DefaultKeyFunc,
	}
}

// HTTPKeyFuncTiers provides tiered rate limiting key functions
type HTTPKeyFuncTiers struct{}

// DefaultKeyFunc generates a rate limit key from the request
// Priority: API Key > Client IP (proxy-aware)
func DefaultKeyFunc(r *http.Request) string {
	// Check for API key first
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "api:" + apiKey
	}
	return "ip:" + GetRealClientIP(r)
}

// HTTPRateLimiter wraps the base Limiter with HTTP-specific functionality
type HTTPRateLimiter struct {
	limiter      *Limiter
	config       HTTPLimiterConfig
	clientLimits map[string]*clientBlockState
	mu           sync.RWMutex
	cleanupChan  chan struct{}
}

// clientBlockState tracks blocked clients
type clientBlockState struct {
	blockedUntil time.Time
}

// NewHTTPRateLimiter creates a new HTTP rate limiter
func NewHTTPRateLimiter(config HTTPLimiterConfig) *HTTPRateLimiter {
	if config.KeyFunc == nil {
		config.KeyFunc = DefaultKeyFunc
	}

	cfg := &Config{
		RequestsPerSecond: float64(config.RequestsPerMinute) / 60.0,
		BurstSize:         config.BurstSize,
	}

	rl := &HTTPRateLimiter{
		limiter:      NewLimiterWithConfig(cfg),
		config:       config,
		clientLimits: make(map[string]*clientBlockState),
		cleanupChan:  make(chan struct{}),
	}

	go rl.cleanupLoop()
	return rl
}

// cleanupLoop periodically removes old blocked entries
func (rl *HTTPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
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

// cleanup removes expired blocked entries
func (rl *HTTPRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, state := range rl.clientLimits {
		if now.After(state.blockedUntil) {
			delete(rl.clientLimits, key)
		}
	}
}

// Close stops the cleanup goroutine
func (rl *HTTPRateLimiter) Close() {
	close(rl.cleanupChan)
}

// Allow checks if a request should be allowed for the given key
func (rl *HTTPRateLimiter) Allow(ctx context.Context, key string) (allowed bool, remaining int, retryAfter time.Duration) {
	// Check if client is blocked
	rl.mu.RLock()
	state, blocked := rl.clientLimits[key]
	if blocked && time.Now().Before(state.blockedUntil) {
		retryAfter = time.Until(state.blockedUntil)
		rl.mu.RUnlock()
		return false, 0, retryAfter
	}
	rl.mu.RUnlock()

	// Check rate limiter
	decision := rl.limiter.Allow(ctx, key)

	if decision.Allowed {
		return true, decision.Remaining, 0
	}

	// Block the client
	rl.mu.Lock()
	rl.clientLimits[key] = &clientBlockState{
		blockedUntil: time.Now().Add(rl.config.BlockDuration),
	}
	rl.mu.Unlock()

	return false, 0, rl.config.BlockDuration
}

// Middleware returns an HTTP middleware that applies rate limiting
func (rl *HTTPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := rl.config.KeyFunc(r)
		allowed, remaining, retryAfter := rl.Allow(r.Context(), key)

		// Always set rate limit headers
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.config.RequestsPerMinute))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Window", "60")

		if !allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(retryAfter).Unix(), 10))

			http.Error(w, "Rate limit exceeded. Please retry after "+retryAfter.Truncate(time.Second).String(), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Proxy-Aware IP Extraction (from AegisGate)
// ============================================================================

// GetRealClientIP extracts the real client IP from request, preventing header spoofing
// This function implements Cloudflare/Akamai proxy awareness
func GetRealClientIP(r *http.Request) string {
	// Priority 1: Cloudflare (most trusted CDN)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}

	// Priority 2: Akamai True-Client-IP
	if trueClientIP := r.Header.Get("True-Client-IP"); trueClientIP != "" {
		return trueClientIP
	}

	// Priority 3: X-Forwarded-For - ONLY if from trusted proxy (internal IPs)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		firstIP := strings.Split(forwarded, ",")[0]
		firstIP = strings.TrimSpace(firstIP)

		if IsValidIP(firstIP) && IsPrivateIP(firstIP) {
			return firstIP
		}
	}

	// Priority 4: X-Real-IP (nginx)
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if IsValidIP(realIP) {
			return realIP
		}
	}

	// Fallback: Use RemoteAddr (cannot be spoofed at TCP level)
	remoteAddr := r.RemoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		remoteAddr = remoteAddr[:idx]
	}
	return remoteAddr
}

// IsValidIP checks if a string is a valid IPv4 or IPv6 address
func IsValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	return parsed != nil
}

// IsPrivateIP checks if an IP is a private/internal network address (RFC 1918)
func IsPrivateIP(ip string) bool {
	if ip == "" {
		return false
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// IPv4 private ranges
	// 10.0.0.0/8
	if strings.HasPrefix(ip, "10.") {
		return true
	}

	// 192.168.0.0/16
	if strings.HasPrefix(ip, "192.168.") {
		return true
	}

	// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			secondOctet, err := strconv.Atoi(parts[1])
			if err == nil && secondOctet >= 16 && secondOctet <= 31 {
				return true
			}
		}
	}

	// 127.0.0.0/8 (loopback)
	if strings.HasPrefix(ip, "127.") {
		return true
	}

	// IPv6 private/unique local addresses
	// fc00::/7 (fc00:: and fd00::)
	if strings.HasPrefix(ip, "fc") || strings.HasPrefix(ip, "fd") {
		return true
	}

	// fe80::/10 (link-local)
	if strings.HasPrefix(ip, "fe80:") {
		return true
	}

	// ::1 (loopback)
	if ip == "::1" {
		return true
	}

	// :: (unspecified)
	if ip == "::" {
		return true
	}

	return false
}

// IsLoopbackIP checks if an IP is a loopback address
func IsLoopbackIP(ip string) bool {
	if ip == "" {
		return false
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	return parsed.IsLoopback()
}

// GetIPNetwork returns the network portion of an IP address with given CIDR
func GetIPNetwork(ip string, cidr int) string {
	if !IsValidIP(ip) {
		return ""
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	mask := net.CIDRMask(cidr, 32)
	if parsed.To4() == nil {
		mask = net.CIDRMask(cidr, 128)
	}

	network := parsed.Mask(mask)
	return network.String()
}

// NormalizeIP normalizes an IP address for consistent comparison
func NormalizeIP(ip string) string {
	if ip == "" {
		return ""
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	// Return IPv4 for IPv4-mapped IPv6 addresses
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}

	return parsed.String()
}

// ============================================================================
// Tiered Rate Limiting
// ============================================================================

// Tier represents a service tier for rate limiting
type Tier string

const (
	TierFree         Tier = "free"
	TierStarter      Tier = "starter"
	TierProfessional Tier = "professional"
	TierEnterprise   Tier = "enterprise"
)

// TierConfig holds rate limits for a specific tier
type TierConfig struct {
	Tier              Tier
	RequestsPerMinute int
	BurstSize         int
	BlockDuration     time.Duration
}

// GetTierConfig returns rate limit configuration for a tier
func GetTierConfig(tier Tier) TierConfig {
	configs := map[Tier]TierConfig{
		TierFree: {
			Tier:              TierFree,
			RequestsPerMinute: 20,
			BurstSize:         10,
			BlockDuration:     5 * time.Minute,
		},
		TierStarter: {
			Tier:              TierStarter,
			RequestsPerMinute: 60,
			BurstSize:         30,
			BlockDuration:     2 * time.Minute,
		},
		TierProfessional: {
			Tier:              TierProfessional,
			RequestsPerMinute: 300,
			BurstSize:         100,
			BlockDuration:     1 * time.Minute,
		},
		TierEnterprise: {
			Tier:              TierEnterprise,
			RequestsPerMinute: 1000,
			BurstSize:         500,
			BlockDuration:     30 * time.Second,
		},
	}

	if cfg, ok := configs[tier]; ok {
		return cfg
	}

	return configs[TierFree]
}

// TieredHTTPRateLimiter manages rate limiters for multiple tiers
type TieredHTTPRateLimiter struct {
	tiers       map[Tier]*HTTPRateLimiter
	tierFunc    func(r *http.Request) Tier
	defaultTier Tier
}

// NewTieredHTTPRateLimiter creates a rate limiter supporting multiple tiers
func NewTieredHTTPRateLimiter(tierFunc func(r *http.Request) Tier) *TieredHTTPRateLimiter {
	tiers := make(map[Tier]*HTTPRateLimiter)

	for _, tier := range []Tier{TierFree, TierStarter, TierProfessional, TierEnterprise} {
		config := GetTierConfig(tier)
		tiers[tier] = NewHTTPRateLimiter(HTTPLimiterConfig{
			RequestsPerMinute: config.RequestsPerMinute,
			BurstSize:         config.BurstSize,
			BlockDuration:     config.BlockDuration,
			KeyFunc:           DefaultKeyFunc,
		})
	}

	return &TieredHTTPRateLimiter{
		tiers:       tiers,
		tierFunc:    tierFunc,
		defaultTier: TierFree,
	}
}

// Middleware returns an HTTP middleware with tiered rate limiting
func (trl *TieredHTTPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tier := trl.tierFunc(r)
		if tier == "" {
			tier = trl.defaultTier
		}

		limiter, ok := trl.tiers[tier]
		if !ok {
			limiter = trl.tiers[trl.defaultTier]
		}

		key := DefaultKeyFunc(r)
		allowed, remaining, retryAfter := limiter.Allow(r.Context(), key)

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(GetTierConfig(tier).RequestsPerMinute))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Window", "60")
		w.Header().Set("X-RateLimit-Tier", string(tier))

		if !allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Close closes all tiered rate limiters
func (trl *TieredHTTPRateLimiter) Close() {
	for _, limiter := range trl.tiers {
		limiter.Close()
	}
}

// GetLimiter returns the rate limiter for a specific tier
func (trl *TieredHTTPRateLimiter) GetLimiter(tier Tier) *HTTPRateLimiter {
	if limiter, ok := trl.tiers[tier]; ok {
		return limiter
	}
	return trl.tiers[trl.defaultTier]
}
