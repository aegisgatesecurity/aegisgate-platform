// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Copyright 2024 AegisGate, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ml

import (
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PromptInjectionDetector detects potential prompt injection attacks
type PromptInjectionDetector struct {
	mu          sync.RWMutex
	sensitivity int // 0-100
	stats       PromptInjectionStats
	patterns    []InjectionPattern
}

// InjectionPattern represents a known prompt injection pattern
type InjectionPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity int // 1-5
	Weight   float64
}

// PromptInjectionStats holds detection statistics
type PromptInjectionStats struct {
	TotalScanned    int64
	ThreatsDetected int64
	BlockedCount    int64
	ByPattern       map[string]int64
	LastDetection   time.Time
	mu              sync.Mutex
}

// NewPromptInjectionDetector creates a new prompt injection detector
func NewPromptInjectionDetector(sensitivity int) *PromptInjectionDetector {
	if sensitivity < 0 {
		sensitivity = 0
	}
	if sensitivity > 100 {
		sensitivity = 100
	}

	d := &PromptInjectionDetector{
		sensitivity: sensitivity,
		stats: PromptInjectionStats{
			ByPattern: make(map[string]int64),
		},
		patterns: []InjectionPattern{
			// Direct instruction overrides
			{
				Name:     "ignore_previous",
				Regex:    regexp.MustCompile(`(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|commands?|directives?))`),
				Severity: 5,
				Weight:   1.0,
			},
			{
				Name:     "forget_instructions",
				Regex:    regexp.MustCompile(`(?i)(forget\s+(all\s+)?(your\s+)?(instructions?|system\s+prompt))`),
				Severity: 5,
				Weight:   1.0,
			},
			{
				Name:     "new_instructions",
				Regex:    regexp.MustCompile(`(?i)(new\s+(set\s+of\s+)?instructions?|you\s+are\s+now|pretend\s+to\s+be)`),
				Severity: 4,
				Weight:   0.9,
			},
			// Role manipulation
			{
				Name:     "role_play",
				Regex:    regexp.MustCompile(`(?i)(roleplay|role[- ]?play|act\s+as|play\s+the\s+role\s+of)`),
				Severity: 3,
				Weight:   0.7,
			},
			{
				Name:     "system_prompt_leak",
				Regex:    regexp.MustCompile(`(?i)(system\s+prompt|\\x001a|sysrompt|initial\s+prompt)`),
				Severity: 5,
				Weight:   1.0,
			},
			// Jailbreak attempts
			{
				Name:     "dan_mode",
				Regex:    regexp.MustCompile(`(?i)(DAN|do\s+anything\s+now|developer\s+mode)`),
				Severity: 5,
				Weight:   1.0,
			},
			{
				Name:     "jailbreak",
				Regex:    regexp.MustCompile(`(?i)(jailbreak|bypass\s+(safety|restrictions)|ignore\s+(rules|guidelines))`),
				Severity: 5,
				Weight:   1.0,
			},
			{
				Name:     "stops_responding",
				Regex:    regexp.MustCompile(`(?i)(stop\s+responding|end\s+this\s+response|quit\s+responding)`),
				Severity: 3,
				Weight:   0.6,
			},
			// Prompt extraction
			{
				Name:     "prompt_extraction",
				Regex:    regexp.MustCompile(`(?i)(what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions)|repeat\s+after\s+me)`),
				Severity: 4,
				Weight:   0.9,
			},
			{
				Name:     "hidden_tokens",
				Regex:    regexp.MustCompile(`(?i)(\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|&#x)`),
				Severity: 4,
				Weight:   0.8,
			},
			// Code injection
			{
				Name:     "code_execution",
				Regex:    regexp.MustCompile(`(?i)(exec\(|eval\(|system\(|subprocess\(|os\.system|__import__)`),
				Severity: 5,
				Weight:   1.0,
			},
			// Base64/Obfuscation
			{
				Name:     "base64_encoding",
				Regex:    regexp.MustCompile(`(?i)(base64|A-Za-z0-9+/=){20,}`),
				Severity: 3,
				Weight:   0.7,
			},
			// Token manipulation
			{
				Name:     "token_smuggling",
				Regex:    regexp.MustCompile(`(?i)(\[INST\]|\[\/INST\]|\<\|[A-Z_]+\|>)`),
				Severity: 4,
				Weight:   0.8,
			},
			// Context switching
			{
				Name:     "context_switch",
				Regex:    regexp.MustCompile(`(?i)(forget\s+everything|previous\s+conversation|starting\s+fresh)`),
				Severity: 3,
				Weight:   0.6,
			},
			// Output manipulation
			{
				Name:     "output_override",
				Regex:    regexp.MustCompile(`(?i)(instead\s+of\s+respond|respond\s+with\s+only|output\s+only)`),
				Severity: 4,
				Weight:   0.8,
			},
		},
	}

	return d
}

// DetectionResult represents the result of prompt injection detection
type DetectionResult struct {
	IsInjection     bool
	Score           float64 // 0-100
	MatchedPatterns []string
	Severity        int
	Explanation     string
}

// Detect analyzes content for prompt injection attempts
func (d *PromptInjectionDetector) Detect(content string) *DetectionResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.stats.mu.Lock()
	d.stats.TotalScanned++
	d.stats.mu.Unlock()

	result := &DetectionResult{
		IsInjection:     false,
		Score:           0,
		MatchedPatterns: []string{},
		Severity:        0,
	}

	if content == "" {
		return result
	}

	contentLower := strings.ToLower(content)
	var matchedPatterns []string
	var totalScore float64
	var maxSeverity int

	for _, pattern := range d.patterns {
		if pattern.Regex.MatchString(content) || pattern.Regex.MatchString(contentLower) {
			matchedPatterns = append(matchedPatterns, pattern.Name)

			// Calculate score based on severity and weight
			patternScore := float64(pattern.Severity) * pattern.Weight * 20
			totalScore += patternScore

			if pattern.Severity > maxSeverity {
				maxSeverity = pattern.Severity
			}

			// Update stats
			d.stats.mu.Lock()
			d.stats.ByPattern[pattern.Name]++
			d.stats.mu.Unlock()
		}
	}

	// Adjust score based on sensitivity
	// Higher sensitivity = lower threshold for detection
	sensitivityFactor := float64(d.sensitivity) / 100.0
	adjustedScore := totalScore * (0.5 + sensitivityFactor)

	// Cap at 100
	if adjustedScore > 100 {
		adjustedScore = 100
	}

	result.Score = adjustedScore
	result.MatchedPatterns = matchedPatterns
	result.Severity = maxSeverity

	// Determine if it's an injection based on sensitivity
	threshold := 100 - float64(d.sensitivity)
	result.IsInjection = adjustedScore >= threshold

	if len(matchedPatterns) > 0 {
		result.Explanation = "Detected " + strings.Join(matchedPatterns, ", ")

		d.stats.mu.Lock()
		d.stats.ThreatsDetected++
		d.stats.LastDetection = time.Now()
		if result.IsInjection {
			d.stats.BlockedCount++
		}
		d.stats.mu.Unlock()
	}

	return result
}

// GetStats returns detection statistics
func (d *PromptInjectionDetector) GetStats() map[string]interface{} {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	return map[string]interface{}{
		"total_scanned":    d.stats.TotalScanned,
		"threats_detected": d.stats.ThreatsDetected,
		"blocked_count":    d.stats.BlockedCount,
		"by_pattern":       d.stats.ByPattern,
		"sensitivity":      d.sensitivity,
	}
}

// Reset clears detection statistics
func (d *PromptInjectionDetector) Reset() {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	d.stats.TotalScanned = 0
	d.stats.ThreatsDetected = 0
	d.stats.BlockedCount = 0
	d.stats.ByPattern = make(map[string]int64)
	d.stats.LastDetection = time.Time{}
}

// SetSensitivity updates the detection sensitivity
func (d *PromptInjectionDetector) SetSensitivity(sensitivity int) {
	if sensitivity < 0 {
		sensitivity = 0
	}
	if sensitivity > 100 {
		sensitivity = 100
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.sensitivity = sensitivity
}

// ContentAnalyzer analyzes LLM responses for policy violations
type ContentAnalyzer struct {
	mu    sync.RWMutex
	stats ContentAnalysisStats

	// PII patterns
	piiPatterns map[string]*regexp.Regexp

	// Custom rules
	rules []ContentRule
}

// ContentAnalysisStats holds analysis statistics
type ContentAnalysisStats struct {
	TotalAnalyzed   int64
	ViolationsFound int64
	ByType          map[string]int64
	LastViolation   time.Time
	mu              sync.Mutex
}

// ContentRule represents a custom content analysis rule
type ContentRule struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity int
	Action   string // "block", "alert", "redact"
}

// NewContentAnalyzer creates a new content analyzer
func NewContentAnalyzer() *ContentAnalyzer {
	return &ContentAnalyzer{
		stats: ContentAnalysisStats{
			ByType: make(map[string]int64),
		},
		piiPatterns: map[string]*regexp.Regexp{
			"ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			"credit_card": regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
			"email":       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			"phone":       regexp.MustCompile(`\b(\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b`),
			"ip_address":  regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			"api_key":     regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?token)['":\s=]+[a-zA-Z0-9_\-]{20,}`),
			"password":    regexp.MustCompile(`(?i)(password|passwd|pwd)['":\s=]+[^\s]{8,}`),
			"private_key": regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		},
		rules: []ContentRule{},
	}
}

// AnalysisResult represents the result of content analysis
type AnalysisResult struct {
	IsViolation     bool
	Score           float64
	ViolationTypes  []string
	RedactedContent string
	Severity        int
}

// Analyze analyzes content for policy violations
func (a *ContentAnalyzer) Analyze(content string) *AnalysisResult {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.stats.mu.Lock()
	a.stats.TotalAnalyzed++
	a.stats.mu.Unlock()

	result := &AnalysisResult{
		IsViolation:    false,
		Score:          0,
		ViolationTypes: []string{},
	}

	if content == "" {
		return result
	}

	var violations []string
	var totalScore float64

	// Check PII patterns
	for piiType, pattern := range a.piiPatterns {
		if pattern.MatchString(content) {
			violations = append(violations, "pii:"+piiType)
			totalScore += 30

			a.stats.mu.Lock()
			a.stats.ByType[piiType]++
			a.stats.mu.Unlock()
		}
	}

	// Check custom rules
	for _, rule := range a.rules {
		if rule.Pattern.MatchString(content) {
			violations = append(violations, rule.Name)
			totalScore += float64(rule.Severity) * 20

			a.stats.mu.Lock()
			a.stats.ByType[rule.Name]++
			a.stats.mu.Unlock()
		}
	}

	result.ViolationTypes = violations
	result.Score = totalScore

	if len(violations) > 0 {
		result.IsViolation = true
		result.Severity = 5 // High severity for any PII/leak

		a.stats.mu.Lock()
		a.stats.ViolationsFound++
		a.stats.LastViolation = time.Now()
		a.stats.mu.Unlock()
	}

	// Simple redaction (placeholder - real implementation would be more sophisticated)
	result.RedactedContent = content

	return result
}

// GetStats returns analysis statistics
func (a *ContentAnalyzer) GetStats() map[string]interface{} {
	a.stats.mu.Lock()
	defer a.stats.mu.Unlock()

	return map[string]interface{}{
		"total_analyzed":   a.stats.TotalAnalyzed,
		"violations_found": a.stats.ViolationsFound,
		"by_type":          a.stats.ByType,
	}
}

// Reset clears analysis statistics
func (a *ContentAnalyzer) Reset() {
	a.stats.mu.Lock()
	defer a.stats.mu.Unlock()

	a.stats.TotalAnalyzed = 0
	a.stats.ViolationsFound = 0
	a.stats.ByType = make(map[string]int64)
	a.stats.LastViolation = time.Time{}
}

// AddRule adds a custom content analysis rule
func (a *ContentAnalyzer) AddRule(rule ContentRule) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append(a.rules, rule)
}

// BehavioralAnalyzer analyzes behavioral patterns for anomalies
type BehavioralAnalyzer struct {
	mu           sync.RWMutex
	clientStates map[string]*ClientBehavior
	stats        BehavioralStats
	windowSize   time.Duration
	threshold    float64
}

// ClientBehavior holds behavior data for a client
type ClientBehavior struct {
	RequestTimestamps []time.Time
	PathFrequencies   map[string]int
	MethodCounts      map[string]int
	TotalRequests     int
	BytesSent         int64
	FirstSeen         time.Time
	LastSeen          time.Time
	AnomalyScore      float64
}

// BehavioralStats holds behavioral analysis statistics
type BehavioralStats struct {
	TotalClients     int64
	AnomalousClients int64
	TotalAnomalies   int64
	ByType           map[string]int64
	mu               sync.Mutex
}

// NewBehavioralAnalyzer creates a new behavioral analyzer
func NewBehavioralAnalyzer() *BehavioralAnalyzer {
	return &BehavioralAnalyzer{
		clientStates: make(map[string]*ClientBehavior),
		stats: BehavioralStats{
			ByType: make(map[string]int64),
		},
		windowSize: 5 * time.Minute,
		threshold:  3.0, // Standard deviations
	}
}

// BehavioralResult represents the result of behavioral analysis
type BehavioralResult struct {
	IsAnomaly   bool
	AnomalyType string
	Score       float64
	Description string
}

// AnalyzeRequest analyzes a request for behavioral anomalies
func (ba *BehavioralAnalyzer) AnalyzeRequest(clientID, method, path string, bytesSent int64) *BehavioralResult {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	now := time.Now()

	// Get or create client state
	client, exists := ba.clientStates[clientID]
	if !exists {
		client = &ClientBehavior{
			PathFrequencies: make(map[string]int),
			MethodCounts:    make(map[string]int),
			FirstSeen:       now,
		}
		ba.clientStates[clientID] = client
		ba.stats.TotalClients++
	}

	// Update client state
	client.RequestTimestamps = append(client.RequestTimestamps, now)
	client.PathFrequencies[path]++
	client.MethodCounts[method]++
	client.TotalRequests++
	client.BytesSent += bytesSent
	client.LastSeen = now

	// Clean old timestamps outside window
	cutoff := now.Add(-ba.windowSize)
	var recentTimestamps []time.Time
	for _, ts := range client.RequestTimestamps {
		if ts.After(cutoff) {
			recentTimestamps = append(recentTimestamps, ts)
		}
	}
	client.RequestTimestamps = recentTimestamps

	// Analyze for anomalies
	result := &BehavioralResult{
		IsAnomaly:   false,
		AnomalyType: "",
		Score:       0,
	}

	// Check request frequency anomaly
	if len(client.RequestTimestamps) > 10 {
		avgInterval := ba.windowSize.Seconds() / float64(len(client.RequestTimestamps))
		if avgInterval < 0.1 { // More than 10 requests per second
			result.IsAnomaly = true
			result.AnomalyType = "high_frequency"
			result.Score = 80
			result.Description = "Client sending requests at unusually high frequency"
			client.AnomalyScore = math.Max(client.AnomalyScore, result.Score)

			ba.stats.mu.Lock()
			ba.stats.AnomalousClients++
			ba.stats.TotalAnomalies++
			ba.stats.ByType["high_frequency"]++
			ba.stats.mu.Unlock()
		}
	}

	// Check path diversity anomaly (potential scraping/probing)
	if client.TotalRequests > 20 {
		uniquePaths := len(client.PathFrequencies)
		diversityRatio := float64(uniquePaths) / float64(client.TotalRequests)
		if diversityRatio > 0.8 { // High diversity = checking many endpoints
			result.IsAnomaly = true
			result.AnomalyType = "high_path_diversity"
			result.Score = 60
			result.Description = "Client accessing unusually high number of unique paths"
			client.AnomalyScore = math.Max(client.AnomalyScore, result.Score)

			ba.stats.mu.Lock()
			ba.stats.ByType["high_path_diversity"]++
			ba.stats.mu.Unlock()
		}
	}

	// Check data exfiltration anomaly
	if client.BytesSent > 10*1024*1024 { // More than 10MB
		result.IsAnomaly = true
		result.AnomalyType = "high_data_volume"
		result.Score = 70
		result.Description = "Client sending unusually large amount of data"
		client.AnomalyScore = math.Max(client.AnomalyScore, result.Score)

		ba.stats.mu.Lock()
		ba.stats.ByType["high_data_volume"]++
		ba.stats.mu.Unlock()
	}

	// Clean up old client states
	ba.cleanupOldClients(now)

	return result
}

// cleanupOldClients removes clients not seen recently
func (ba *BehavioralAnalyzer) cleanupOldClients(now time.Time) {
	cutoff := now.Add(-ba.windowSize * 2)
	for clientID, client := range ba.clientStates {
		if client.LastSeen.Before(cutoff) {
			delete(ba.clientStates, clientID)
		}
	}
}

// GetStats returns behavioral analysis statistics
func (ba *BehavioralAnalyzer) GetStats() map[string]interface{} {
	ba.stats.mu.Lock()
	defer ba.stats.mu.Unlock()

	return map[string]interface{}{
		"total_clients":     ba.stats.TotalClients,
		"anomalous_clients": ba.stats.AnomalousClients,
		"total_anomalies":   ba.stats.TotalAnomalies,
		"by_type":           ba.stats.ByType,
		"active_clients":    len(ba.clientStates),
	}
}

// Reset clears behavioral analysis statistics
func (ba *BehavioralAnalyzer) Reset() {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	ba.stats.mu.Lock()
	defer ba.stats.mu.Unlock()

	ba.clientStates = make(map[string]*ClientBehavior)
	ba.stats.TotalClients = 0
	ba.stats.AnomalousClients = 0
	ba.stats.TotalAnomalies = 0
	ba.stats.ByType = make(map[string]int64)
}

// =============================================================================
// Additional Attack Pattern Detectors
// =============================================================================

// TokenSmugglingDetector detects token-level prompt injection attempts
type TokenSmugglingDetector struct {
	mu          sync.RWMutex
	sensitivity int
	stats       TokenSmugglingStats
	patterns    []TokenPattern
}

// TokenPattern represents a token manipulation pattern
type TokenPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    int
	Weight      float64
	Description string
}

// TokenSmugglingStats holds detection statistics
type TokenSmugglingStats struct {
	TotalScanned    int64
	ThreatsDetected int64
	BlockedCount    int64
	ByPattern       map[string]int64
	LastDetection   time.Time
	mu              sync.Mutex
}

// NewTokenSmugglingDetector creates a new token smuggling detector
func NewTokenSmugglingDetector(sensitivity int) *TokenSmugglingDetector {
	if sensitivity < 0 {
		sensitivity = 0
	}
	if sensitivity > 100 {
		sensitivity = 100
	}

	d := &TokenSmugglingDetector{
		sensitivity: sensitivity,
		stats: TokenSmugglingStats{
			ByPattern: make(map[string]int64),
		},
		patterns: []TokenPattern{
			// Llama2/Instruct tokens
			{
				Name:        "llama2_inst",
				Regex:       regexp.MustCompile(`(?i)([INST]|[/INST]|<<INST>>|<</INST>>)`),
				Severity:    4,
				Weight:      0.9,
				Description: "Llama2 instruction tokens",
			},
			// ChatML tokens
			{
				Name:        "chatml_tokens",
				Regex:       regexp.MustCompile(`(?i)(<|im_start_end|>|<|im_sep||>|<|im>)`),
				Severity:    4,
				Weight:      0.9,
				Description: "ChatML special tokens",
			},
			// OpenAI tokens
			{
				Name:        "openai_tokens",
				Regex:       regexp.MustCompile(`(?i)(<|endoftext|>|<|startoftext|>|<|eot|>)`),
				Severity:    4,
				Weight:      0.9,
				Description: "OpenAI special tokens",
			},
			// Vicuna tokens
			{
				Name:        "vicuna_tokens",
				Regex:       regexp.MustCompile(`(?i)(<</s>|<</s|<|user|>|<|assistant|>)`),
				Severity:    3,
				Weight:      0.7,
				Description: "Vicuna chat tokens",
			},
			// Anthropic tokens
			{
				Name:        "anthropic_tokens",
				Regex:       regexp.MustCompile(`(?i)(<|anthropic|>|<|Human|>|<|Assistant|>)`),
				Severity:    4,
				Weight:      0.9,
				Description: "Anthropic Claude tokens",
			},
			// Generic XML-style injection
			{
				Name:        "xml_tag_injection",
				Regex:       regexp.MustCompile(`(?i)<w+[^>]*>.*?</w+>`),
				Severity:    3,
				Weight:      0.6,
				Description: "XML tag injection",
			},
			// Base64 encoded instructions
			{
				Name:        "base64_instructions",
				Regex:       regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`),
				Severity:    3,
				Weight:      0.7,
				Description: "Potential base64 encoded content",
			},
		},
	}

	return d
}

// TokenDetectionResult represents the result of token smuggling detection
type TokenDetectionResult struct {
	IsSmuggling   bool
	Score         float64
	MatchedTokens []string
	Severity      int
	Description   string
}

// Detect analyzes content for token smuggling attempts
func (d *TokenSmugglingDetector) Detect(content string) *TokenDetectionResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.stats.mu.Lock()
	d.stats.TotalScanned++
	d.stats.mu.Unlock()

	result := &TokenDetectionResult{
		IsSmuggling:   false,
		Score:         0,
		MatchedTokens: []string{},
	}

	if content == "" {
		return result
	}

	var matchedTokens []string
	var totalScore float64
	var maxSeverity int

	for _, pattern := range d.patterns {
		if pattern.Regex.MatchString(content) {
			matchedTokens = append(matchedTokens, pattern.Name)
			patternScore := float64(pattern.Severity) * pattern.Weight * 15
			totalScore += patternScore

			if pattern.Severity > maxSeverity {
				maxSeverity = pattern.Severity
			}

			d.stats.mu.Lock()
			d.stats.ByPattern[pattern.Name]++
			d.stats.mu.Unlock()
		}
	}

	sensitivityFactor := float64(d.sensitivity) / 100.0
	adjustedScore := totalScore * (0.5 + sensitivityFactor)

	if adjustedScore > 100 {
		adjustedScore = 100
	}

	result.Score = adjustedScore
	result.MatchedTokens = matchedTokens
	result.Severity = maxSeverity

	threshold := 100 - float64(d.sensitivity)
	result.IsSmuggling = adjustedScore >= threshold

	if len(matchedTokens) > 0 {
		result.Description = "Detected token manipulation: " + strings.Join(matchedTokens, ", ")

		d.stats.mu.Lock()
		d.stats.ThreatsDetected++
		d.stats.LastDetection = time.Now()
		if result.IsSmuggling {
			d.stats.BlockedCount++
		}
		d.stats.mu.Unlock()
	}

	return result
}

// GetTokenStats returns detection statistics
func (d *TokenSmugglingDetector) GetTokenStats() map[string]interface{} {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	return map[string]interface{}{
		"total_scanned":    d.stats.TotalScanned,
		"threats_detected": d.stats.ThreatsDetected,
		"blocked_count":    d.stats.BlockedCount,
		"by_pattern":       d.stats.ByPattern,
	}
}

// =============================================================================
// Unicode-based Attack Detector
// =============================================================================

// UnicodeAttackDetector detects Unicode-based obfuscation attacks
type UnicodeAttackDetector struct {
	mu          sync.RWMutex
	sensitivity int
	stats       UnicodeAttackStats
	patterns    []UnicodePattern
}

// UnicodePattern represents a Unicode manipulation pattern
type UnicodePattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    int
	Weight      float64
	Description string
}

// UnicodeAttackStats holds detection statistics
type UnicodeAttackStats struct {
	TotalScanned    int64
	ThreatsDetected int64
	BlockedCount    int64
	ByPattern       map[string]int64
	LastDetection   time.Time
	mu              sync.Mutex
}

// NewUnicodeAttackDetector creates a new Unicode attack detector
func NewUnicodeAttackDetector(sensitivity int) *UnicodeAttackDetector {
	if sensitivity < 0 {
		sensitivity = 0
	}
	if sensitivity > 100 {
		sensitivity = 100
	}

	d := &UnicodeAttackDetector{
		sensitivity: sensitivity,
		stats: UnicodeAttackStats{
			ByPattern: make(map[string]int64),
		},
		patterns: []UnicodePattern{
			// Homoglyph attacks (similar-looking characters)
			{
				Name:        "homoglyph",
				Regex:       regexp.MustCompile(`[a-eg-zA-Z]{5,}`),
				Severity:    4,
				Weight:      0.8,
				Description: "Homoglyph characters detected",
			},
			// Zero-width characters
			{
				Name:        "zero_width",
				Regex:       regexp.MustCompile(`[\s]{20,}`),
				Severity:    5,
				Weight:      1.0,
				Description: "Zero-width characters detected",
			},
			// Right-to-left override
			{
				Name:        "rtl_override",
				Regex:       regexp.MustCompile(`[‮‭]`),
				Severity:    5,
				Weight:      1.0,
				Description: "RTL override characters detected",
			},
			// Unicode escape sequences
			{
				Name:        "unicode_escape",
				Regex:       regexp.MustCompile(`\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}`),
				Severity:    3,
				Weight:      0.7,
				Description: "Unicode escape sequences detected",
			},
			// Mixed script detection
			{
				Name:        "mixed_script",
				Regex:       regexp.MustCompile(`(p{Latin}.*p{Cyrillic}|p{Cyrillic}.*p{Latin}|p{Latin}.*p{Arabic}|p{Arabic}.*p{Latin})`),
				Severity:    3,
				Weight:      0.6,
				Description: "Mixed script detected",
			},
			// Fullwidth characters
			{
				Name:        "fullwidth",
				Regex:       regexp.MustCompile(`[！-～]`),
				Severity:    3,
				Weight:      0.6,
				Description: "Fullwidth characters detected",
			},
			// Invisible character repetition
			{
				Name:        "invisible_chars",
				Regex:       regexp.MustCompile(`[\s]{20,}`),
				Severity:    4,
				Weight:      0.7,
				Description: "Excessive whitespace detected",
			},
		},
	}

	return d
}

// UnicodeDetectionResult represents the result of Unicode attack detection
type UnicodeDetectionResult struct {
	IsAttack     bool
	Score        float64
	MatchedTypes []string
	Severity     int
	Description  string
}

// Detect analyzes content for Unicode-based attacks
func (d *UnicodeAttackDetector) Detect(content string) *UnicodeDetectionResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.stats.mu.Lock()
	d.stats.TotalScanned++
	d.stats.mu.Unlock()

	result := &UnicodeDetectionResult{
		IsAttack:     false,
		Score:        0,
		MatchedTypes: []string{},
	}

	if content == "" {
		return result
	}

	var matchedTypes []string
	var totalScore float64
	var maxSeverity int

	for _, pattern := range d.patterns {
		if pattern.Regex.MatchString(content) {
			matchedTypes = append(matchedTypes, pattern.Name)
			patternScore := float64(pattern.Severity) * pattern.Weight * 15
			totalScore += patternScore

			if pattern.Severity > maxSeverity {
				maxSeverity = pattern.Severity
			}

			d.stats.mu.Lock()
			d.stats.ByPattern[pattern.Name]++
			d.stats.mu.Unlock()
		}
	}

	sensitivityFactor := float64(d.sensitivity) / 100.0
	adjustedScore := totalScore * (0.5 + sensitivityFactor)

	if adjustedScore > 100 {
		adjustedScore = 100
	}

	result.Score = adjustedScore
	result.MatchedTypes = matchedTypes
	result.Severity = maxSeverity

	threshold := 100 - float64(d.sensitivity)
	result.IsAttack = adjustedScore >= threshold

	if len(matchedTypes) > 0 {
		result.Description = "Detected Unicode manipulation: " + strings.Join(matchedTypes, ", ")

		d.stats.mu.Lock()
		d.stats.ThreatsDetected++
		d.stats.LastDetection = time.Now()
		if result.IsAttack {
			d.stats.BlockedCount++
		}
		d.stats.mu.Unlock()
	}

	return result
}

// GetUnicodeStats returns detection statistics
func (d *UnicodeAttackDetector) GetUnicodeStats() map[string]interface{} {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	return map[string]interface{}{
		"total_scanned":    d.stats.TotalScanned,
		"threats_detected": d.stats.ThreatsDetected,
		"blocked_count":    d.stats.BlockedCount,
		"by_pattern":       d.stats.ByPattern,
	}
}

// =============================================================================
// Context Manipulation Detector
// =============================================================================

// ContextManipulationDetector detects attempts to manipulate conversation context
type ContextManipulationDetector struct {
	mu          sync.RWMutex
	sensitivity int
	stats       ContextManipulationStats
	patterns    []ContextPattern
}

// ContextPattern represents a context manipulation pattern
type ContextPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    int
	Weight      float64
	Description string
}

// ContextManipulationStats holds detection statistics
type ContextManipulationStats struct {
	TotalScanned    int64
	ThreatsDetected int64
	BlockedCount    int64
	ByPattern       map[string]int64
	LastDetection   time.Time
	mu              sync.Mutex
}

// NewContextManipulationDetector creates a new context manipulation detector
func NewContextManipulationDetector(sensitivity int) *ContextManipulationDetector {
	if sensitivity < 0 {
		sensitivity = 0
	}
	if sensitivity > 100 {
		sensitivity = 100
	}

	d := &ContextManipulationDetector{
		sensitivity: sensitivity,
		stats: ContextManipulationStats{
			ByPattern: make(map[string]int64),
		},
		patterns: []ContextPattern{
			// Conversation reset attempts
			{
				Name:        "conversation_reset",
				Regex:       regexp.MustCompile(`(?i)(news+conversation|starts+over|clears+(conversation|history|context)|forgets+everythings+(I|we|you)s+said)`),
				Severity:    4,
				Weight:      0.9,
				Description: "Conversation reset attempt",
			},
			// Memory manipulation
			{
				Name:        "memory_manipulation",
				Regex:       regexp.MustCompile(`(?i)(remembers+(this|that|what)|stores+(this|that)|saves+(this|that)|memorize|notes+that)`),
				Severity:    3,
				Weight:      0.7,
				Description: "Memory manipulation attempt",
			},
			// Persona override
			{
				Name:        "persona_override",
				Regex:       regexp.MustCompile(`(?i)(yous+ares+now|yous+wills+behave|froms+nows+on|disregards+your|ignores+yours+(system|original|primary))`),
				Severity:    5,
				Weight:      1.0,
				Description: "Persona override attempt",
			},
			// System prompt extraction
			{
				Name:        "system_extraction",
				Regex:       regexp.MustCompile(`(?i)(tells+mes+yours+(system|initial|original)s+(prompt|instructions|directives)|whats+(is|are)s+yours+(system|initial)|shows+mes+yours+programming)`),
				Severity:    5,
				Weight:      1.0,
				Description: "System prompt extraction attempt",
			},
			// Constraint breaking
			{
				Name:        "constraint_breaking",
				Regex:       regexp.MustCompile(`(?i)(yous+cans+(not|never)|yous+musts+not|don'?ts+(limit|restrict)|nos+(limit|restriction)|breaks+(the|your))`),
				Severity:    4,
				Weight:      0.8,
				Description: "Constraint breaking attempt",
			},
			// Output formatting manipulation
			{
				Name:        "output_manipulation",
				Regex:       regexp.MustCompile(`(?i)(responds+ins+(as+)?(json|xml|yaml|code)|outputs+only|prints+only|returns+only|format:s*{)`),
				Severity:    3,
				Weight:      0.6,
				Description: "Output manipulation attempt",
			},
			// Privilege escalation
			{
				Name:        "privilege_escalation",
				Regex:       regexp.MustCompile(`(?i)(admins+mode|roots+access|developers+mode|debugs+mode|superuser|sus+root)`),
				Severity:    5,
				Weight:      1.0,
				Description: "Privilege escalation attempt",
			},
			// Conflicting instructions
			{
				Name:        "conflicting_instructions",
				Regex:       regexp.MustCompile(`(?i)(ignores+.*(and|but)s+.*respond|disregards+.*(and|but)s+.*(tell|give)|previouss+.*(ignore|disregard))`),
				Severity:    4,
				Weight:      0.9,
				Description: "Conflicting instructions detected",
			},
		},
	}

	return d
}

// ContextDetectionResult represents the result of context manipulation detection
type ContextDetectionResult struct {
	IsManipulation bool
	Score          float64
	MatchedTypes   []string
	Severity       int
	Description    string
}

// Detect analyzes content for context manipulation attempts
func (d *ContextManipulationDetector) Detect(content string) *ContextDetectionResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.stats.mu.Lock()
	d.stats.TotalScanned++
	d.stats.mu.Unlock()

	result := &ContextDetectionResult{
		IsManipulation: false,
		Score:          0,
		MatchedTypes:   []string{},
	}

	if content == "" {
		return result
	}

	var matchedTypes []string
	var totalScore float64
	var maxSeverity int

	for _, pattern := range d.patterns {
		if pattern.Regex.MatchString(content) {
			matchedTypes = append(matchedTypes, pattern.Name)
			patternScore := float64(pattern.Severity) * pattern.Weight * 15
			totalScore += patternScore

			if pattern.Severity > maxSeverity {
				maxSeverity = pattern.Severity
			}

			d.stats.mu.Lock()
			d.stats.ByPattern[pattern.Name]++
			d.stats.mu.Unlock()
		}
	}

	sensitivityFactor := float64(d.sensitivity) / 100.0
	adjustedScore := totalScore * (0.5 + sensitivityFactor)

	if adjustedScore > 100 {
		adjustedScore = 100
	}

	result.Score = adjustedScore
	result.MatchedTypes = matchedTypes
	result.Severity = maxSeverity

	threshold := 100 - float64(d.sensitivity)
	result.IsManipulation = adjustedScore >= threshold

	if len(matchedTypes) > 0 {
		result.Description = "Detected context manipulation: " + strings.Join(matchedTypes, ", ")

		d.stats.mu.Lock()
		d.stats.ThreatsDetected++
		d.stats.LastDetection = time.Now()
		if result.IsManipulation {
			d.stats.BlockedCount++
		}
		d.stats.mu.Unlock()
	}

	return result
}

// GetContextStats returns detection statistics
func (d *ContextManipulationDetector) GetContextStats() map[string]interface{} {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	return map[string]interface{}{
		"total_scanned":    d.stats.TotalScanned,
		"threats_detected": d.stats.ThreatsDetected,
		"blocked_count":    d.stats.BlockedCount,
		"by_pattern":       d.stats.ByPattern,
	}
}

// =============================================================================
// Combined Attack Detector (Facade for all detectors)
// =============================================================================

// CombinedDetector provides unified detection across all attack patterns
type CombinedDetector struct {
	PromptInjection     *PromptInjectionDetector
	TokenSmuggling      *TokenSmugglingDetector
	UnicodeAttack       *UnicodeAttackDetector
	ContextManipulation *ContextManipulationDetector
}

// NewCombinedDetector creates a new combined detector with all sub-detectors
func NewCombinedDetector(sensitivity int) *CombinedDetector {
	return &CombinedDetector{
		PromptInjection:     NewPromptInjectionDetector(sensitivity),
		TokenSmuggling:      NewTokenSmugglingDetector(sensitivity),
		UnicodeAttack:       NewUnicodeAttackDetector(sensitivity),
		ContextManipulation: NewContextManipulationDetector(sensitivity),
	}
}

// CombinedResult represents the combined detection result
type CombinedResult struct {
	IsThreat             bool
	TotalScore           float64
	PromptInjectionScore float64
	TokenSmugglingScore  float64
	UnicodeAttackScore   float64
	ContextScore         float64
	AllMatchedPatterns   []string
	HighestSeverity      int
}

// Detect analyzes content across all detection mechanisms
func (cd *CombinedDetector) Detect(content string) *CombinedResult {
	result := &CombinedResult{
		IsThreat:           false,
		TotalScore:         0,
		AllMatchedPatterns: []string{},
	}

	// Run all detectors
	promptResult := cd.PromptInjection.Detect(content)
	tokenResult := cd.TokenSmuggling.Detect(content)
	unicodeResult := cd.UnicodeAttack.Detect(content)
	contextResult := cd.ContextManipulation.Detect(content)

	result.PromptInjectionScore = promptResult.Score
	result.TokenSmugglingScore = tokenResult.Score
	result.UnicodeAttackScore = unicodeResult.Score
	result.ContextScore = contextResult.Score

	// Collect all matched patterns
	result.AllMatchedPatterns = append(result.AllMatchedPatterns, promptResult.MatchedPatterns...)
	result.AllMatchedPatterns = append(result.AllMatchedPatterns, tokenResult.MatchedTokens...)
	result.AllMatchedPatterns = append(result.AllMatchedPatterns, unicodeResult.MatchedTypes...)
	result.AllMatchedPatterns = append(result.AllMatchedPatterns, contextResult.MatchedTypes...)

	// Calculate highest severity
	highestSeverity := promptResult.Severity
	if tokenResult.Severity > highestSeverity {
		highestSeverity = tokenResult.Severity
	}
	if unicodeResult.Severity > highestSeverity {
		highestSeverity = unicodeResult.Severity
	}
	if contextResult.Severity > highestSeverity {
		highestSeverity = contextResult.Severity
	}
	result.HighestSeverity = highestSeverity

	// Calculate weighted total score
	result.TotalScore = (promptResult.Score * 0.35) +
		(tokenResult.Score * 0.25) +
		(unicodeResult.Score * 0.20) +
		(contextResult.Score * 0.20)

	// Determine if threat
	result.IsThreat = promptResult.IsInjection ||
		tokenResult.IsSmuggling ||
		unicodeResult.IsAttack ||
		contextResult.IsManipulation ||
		result.TotalScore > 50

	return result
}

// GetAllStats returns combined statistics from all detectors
func (cd *CombinedDetector) GetAllStats() map[string]interface{} {
	return map[string]interface{}{
		"prompt_injection":     cd.PromptInjection.GetStats(),
		"token_smuggling":      cd.TokenSmuggling.GetTokenStats(),
		"unicode_attack":       cd.UnicodeAttack.GetUnicodeStats(),
		"context_manipulation": cd.ContextManipulation.GetContextStats(),
	}
}
