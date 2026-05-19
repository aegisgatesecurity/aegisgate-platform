// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Token Limiter
// =========================================================================

package response

import (
	"sync"
	"time"
)

// TokenLimiter tracks and limits token usage per client
type TokenLimiter struct {
	config *TokenLimiterConfig
	usage  map[string][]tokenEntry
	mu     sync.RWMutex
}

type tokenEntry struct {
	tokens   int
	timestamp time.Time
}

// NewTokenLimiter creates a new token limiter with default config
func NewTokenLimiter(config *TokenLimiterConfig) *TokenLimiter {
	if config == nil {
		config = DefaultTokenLimiterConfig()
	}
	return &TokenLimiter{
		config: config,
		usage:  make(map[string][]tokenEntry),
	}
}

// CountTokens approximates the number of tokens in text
func (tl *TokenLimiter) CountTokens(text string) int {
	// Simple approximation: words + 20% for average token overhead
	wordCount := 0
	inWord := false
	for _, c := range text {
		if c == ' ' || c == '\n' || c == '\t' {
			inWord = false
		} else if !inWord {
			wordCount++
			inWord = true
		}
	}
	// Rough estimate: 1 token ≈ 0.75 words for English
	return int(float64(wordCount) / 0.75)
}

// AllowToken checks if a token count is allowed for the client
func (tl *TokenLimiter) AllowToken(clientID string, tokens int) (bool, string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-tl.config.WindowDuration)

	// Clean old entries
	entries := tl.usage[clientID]
	var validEntries []tokenEntry
	for _, e := range entries {
		if e.timestamp.After(windowStart) {
			validEntries = append(validEntries, e)
		}
	}

	// Calculate current usage
	totalTokens := 0
	requestCount := len(validEntries)
	for _, e := range validEntries {
		totalTokens += e.tokens
	}

	// Check token rate limit
	if totalTokens+tokens > tl.config.TokensPerMinute {
		return false, "Token rate limit exceeded"
	}

	// Check request rate limit
	if requestCount+1 > tl.config.MaxResponsesPerMinute {
		return false, "Request rate limit exceeded"
	}

	// Check max tokens per response
	if tokens > tl.config.MaxTokensPerResponse {
		return false, "Response too large"
	}

	// Add new entry
	tl.usage[clientID] = append(validEntries, tokenEntry{
		tokens:   tokens,
		timestamp: now,
	})

	return true, ""
}

// GetUsage returns current usage for a client
func (tl *TokenLimiter) GetUsage(clientID string) (tokens int, requests int) {
	tl.mu.RLock()
	defer tl.mu.RUnlock()

	now := time.Now()
	windowStart := now.Add(-tl.config.WindowDuration)

	entries := tl.usage[clientID]
	totalTokens := 0
	validCount := 0
	for _, e := range entries {
		if e.timestamp.After(windowStart) {
			totalTokens += e.tokens
			validCount++
		}
	}

	return totalTokens, validCount
}

// ResetUsage resets usage for a client
func (tl *TokenLimiter) ResetUsage(clientID string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	delete(tl.usage, clientID)
}

// ResetAll resets all usage
func (tl *TokenLimiter) ResetAll() {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.usage = make(map[string][]tokenEntry)
}