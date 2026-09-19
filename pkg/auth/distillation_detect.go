// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Distillation Attack Detection (v4.5.0)
// =========================================================================
// distillation_detect.go detects patterns associated with AI model
// distillation attacks — systematic extraction of model capabilities
// via stolen API keys, proxy services, and coordinated account clusters.
//
// Addresses 4 in-scope gaps from the 90-day threat landscape analysis:
//
//   GAP-DIST2: Proxy service detection (known relay IPs)
//   GAP-DIST3: Distillation pattern recognition (systematic CoT extraction)
//   GAP-DIST4: Account clustering (3,500+ accounts same behavior)
//   GAP-DIST5: Stolen key detection (behavioral indicators)
//
// All detection is non-blocking (alert-only). The detector logs warnings
// and populates metadata for downstream SIEM/alerting. Blocking is a
// policy decision made by the operator, not by this detector.
// =========================================================================

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

// =========================================================================
// GAP-DIST2: Proxy Service Detection
// =========================================================================

// KnownProxyRanges are IP ranges commonly used by AI proxy/relay services.
// These are datacenter/hosting ranges where relay services typically run.
// Legitimate users access AI APIs from corporate or residential IPs.
// Requests from these ranges get a higher proxy-likelihood score.
var KnownProxyRanges = []string{
	// DigitalOcean
	"159.203.0.0/16", "165.22.0.0/16", "167.71.0.0/16", "167.99.0.0/16",
	// AWS (common relay host)
	"3.0.0.0/9", "3.128.0.0/9", "13.0.0.0/8",
	// Linode/Akamai
	"45.33.0.0/17", "45.56.0.0/17", "139.144.0.0/16",
	// Vultr
	"45.32.0.0/16", "45.63.0.0/16", "45.77.0.0/16",
	// Oracle Cloud
	"129.146.0.0/16", "132.145.0.0/16",
	// Hetzner (common for EU relay services)
	"49.12.0.0/16", "49.13.0.0/16", "65.108.0.0/16", "65.109.0.0/16",
	// Contabo (budget hosting, common for relay farms)
	"194.163.128.0/19", "161.97.0.0/17",
}

// ProxyServiceDetector identifies requests likely coming from AI proxy services.
type ProxyServiceDetector struct {
	cidrs         []*net.IPNet
	datacenterIPs sync.Map // IP → first-seen timestamp
	mu            sync.RWMutex
}

// NewProxyServiceDetector creates a detector with known relay ranges.
func NewProxyServiceDetector() *ProxyServiceDetector {
	detector := &ProxyServiceDetector{}
	for _, cidr := range KnownProxyRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			detector.cidrs = append(detector.cidrs, ipNet)
		}
	}
	return detector
}

// ProxyServiceResult indicates whether an IP is likely a proxy/relay service.
type ProxyServiceResult struct {
	IsProxy      bool
	IsDatacenter bool
	Confidence   float64
	Reason       string
}

// CheckIP evaluates whether an IP address is a known proxy/datacenter range.
func (d *ProxyServiceDetector) CheckIP(ipStr string) ProxyServiceResult {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ProxyServiceResult{Confidence: 0}
	}

	for _, cidr := range d.cidrs {
		if cidr.Contains(ip) {
			return ProxyServiceResult{
				IsProxy:      true,
				IsDatacenter: true,
				Confidence:   0.85,
				Reason:       "IP in known datacenter/proxy range",
			}
		}
	}

	return ProxyServiceResult{Confidence: 0}
}

// RecordDatacenterIP tracks repeated access from datacenter IPs.
func (d *ProxyServiceDetector) RecordDatacenterIP(ipStr string) {
	if d.CheckIP(ipStr).IsDatacenter {
		d.datacenterIPs.Store(ipStr, time.Now())
	}
}

// GetDatacenterIPCount returns the number of unique datacenter IPs seen.
func (d *ProxyServiceDetector) GetDatacenterIPCount() int {
	count := 0
	d.datacenterIPs.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// =========================================================================
// GAP-DIST3: Distillation Pattern Recognition
// =========================================================================

// DistillationPatternDetector identifies systematic Chain-of-Thought (CoT)
// extraction — repeated similar prompts designed to harvest reasoning traces.
//
// Attack pattern (from Claude distillation incident):
//   - 151M exchanges from 3,500+ accounts
//   - Peak: 3M exchanges/day
//   - Systematic: similar prompt structures, high volume, CoT-heavy requests
type DistillationPatternDetector struct {
	sessions map[string]*distillationSession
	mu       sync.RWMutex
	window   time.Duration
}

type distillationSession struct {
	keyID           string
	promptHashes    map[string]int // hash → count (similarity detection)
	promptCount     int
	cotRequestCount int // prompts that explicitly request reasoning
	firstSeen       time.Time
	lastSeen        time.Time
	ipSet           map[string]bool
}

// NewDistillationPatternDetector creates a detector for CoT extraction patterns.
func NewDistillationPatternDetector() *DistillationPatternDetector {
	return &DistillationPatternDetector{
		sessions: make(map[string]*distillationSession),
		window:   1 * time.Hour,
	}
}

// DistillationResult indicates whether a key shows distillation patterns.
type DistillationResult struct {
	KeyID           string
	IsDistillation  bool
	Confidence      float64
	Flags           []string
	PromptCount     int
	SimilarityScore float64
	CoTRequestRatio float64
	UniqueIPCount   int
}

// CoT indicators — phrases that signal Chain-of-Thought extraction
var cotIndicators = []string{
	"step by step", "step-by-step", "chain of thought", "reasoning trace",
	"think through", "show your reasoning", "explain your reasoning",
	"walk me through", "break it down", "let's think step by step",
	"reasoning steps", "thought process", "detailed reasoning",
	"explain step by step", "show your work", "reasoning chain",
}

// RecordPrompt records a prompt from a key for distillation pattern analysis.
func (d *DistillationPatternDetector) RecordPrompt(keyID, prompt, sourceIP string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	session, ok := d.sessions[keyID]
	if !ok {
		session = &distillationSession{
			keyID:        keyID,
			promptHashes: make(map[string]int),
			ipSet:        make(map[string]bool),
			firstSeen:    time.Now(),
		}
		d.sessions[keyID] = session
	}

	now := time.Now()
	session.lastSeen = now
	session.promptCount++

	// Hash the prompt structure (normalize + hash for similarity)
	hash := hashPromptStructure(prompt)
	session.promptHashes[hash]++

	// Check for CoT request indicators
	promptLower := strings.ToLower(prompt)
	for _, indicator := range cotIndicators {
		if strings.Contains(promptLower, indicator) {
			session.cotRequestCount++
			break
		}
	}

	// Track IP diversity
	if sourceIP != "" {
		session.ipSet[sourceIP] = true
	}
}

// AnalyzeKey evaluates whether a key shows distillation attack patterns.
func (d *DistillationPatternDetector) AnalyzeKey(keyID string) DistillationResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	session, ok := d.sessions[keyID]
	if !ok {
		return DistillationResult{KeyID: keyID}
	}

	result := DistillationResult{
		KeyID:         keyID,
		PromptCount:   session.promptCount,
		UniqueIPCount: len(session.ipSet),
	}

	// Factor 1: High volume (>100 prompts/hour from single key = suspicious)
	if session.promptCount > 100 {
		result.Confidence += 0.3
		result.Flags = append(result.Flags, "high_volume_single_key")
	}

	// Factor 2: Prompt similarity (same structure hash appearing >20 times)
	maxSimilarity := 0
	totalHashes := 0
	for _, count := range session.promptHashes {
		if count > maxSimilarity {
			maxSimilarity = count
		}
		totalHashes += count
	}
	if totalHashes > 0 {
		result.SimilarityScore = float64(maxSimilarity) / float64(totalHashes)
		if result.SimilarityScore > 0.3 && session.promptCount > 20 {
			result.Confidence += 0.25
			result.Flags = append(result.Flags, "high_prompt_similarity")
		}
	}

	// Factor 3: High CoT request ratio (>60% of prompts request reasoning)
	if session.promptCount > 10 {
		cotRatio := float64(session.cotRequestCount) / float64(session.promptCount)
		result.CoTRequestRatio = cotRatio
		if cotRatio > 0.6 {
			result.Confidence += 0.35
			result.Flags = append(result.Flags, "systematic_cot_extraction")
		}
	}

	// Factor 4: Multiple IPs for single key (key sharing or proxy rotation)
	if len(session.ipSet) > 5 {
		result.Confidence += 0.15
		result.Flags = append(result.Flags, "multi_ip_key_usage")
	}

	// Cap at 1.0
	if result.Confidence > 1.0 {
		result.Confidence = 1.0
	}

	result.IsDistillation = result.Confidence >= 0.6

	return result
}

// CleanupExpired removes sessions older than the window.
func (d *DistillationPatternDetector) CleanupExpired() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	removed := 0
	for keyID, session := range d.sessions {
		if now.Sub(session.lastSeen) > d.window {
			delete(d.sessions, keyID)
			removed++
		}
	}
	return removed
}

// hashPromptStructure creates a structural hash of a prompt for similarity detection.
// Normalizes whitespace, lowercases, removes digits/variable content, then hashes.
func hashPromptStructure(prompt string) string {
	// Normalize: lowercase, collapse whitespace, remove digits
	normalized := strings.ToLower(prompt)
	normalized = strings.Join(strings.Fields(normalized), " ")
	// Remove standalone numbers (variable content like IDs, counts)
	normalized = strings.ReplaceAll(normalized, "0", "")
	normalized = strings.ReplaceAll(normalized, "1", "")
	normalized = strings.ReplaceAll(normalized, "2", "")
	normalized = strings.ReplaceAll(normalized, "3", "")
	normalized = strings.ReplaceAll(normalized, "4", "")
	normalized = strings.ReplaceAll(normalized, "5", "")
	normalized = strings.ReplaceAll(normalized, "6", "")
	normalized = strings.ReplaceAll(normalized, "7", "")
	normalized = strings.ReplaceAll(normalized, "8", "")
	normalized = strings.ReplaceAll(normalized, "9", "")
	normalized = strings.Join(strings.Fields(normalized), " ")

	// If too short after normalization, use as-is
	if len(normalized) < 10 {
		return normalized
	}

	// Use first 50 chars as structure key (catches "explain step by step how to..." variants)
	if len(normalized) > 50 {
		normalized = normalized[:50]
	}

	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:8])
}

// =========================================================================
// GAP-DIST4: Account Clustering Analysis
// =========================================================================

// AccountClusterDetector identifies groups of API keys exhibiting identical
// behavioral patterns — indicating coordinated distillation campaigns.
//
// Attack pattern (from Claude incident):
//   - 3,500+ fraudulent accounts in GTG-16005
//   - 5,380 accounts in GTG-16002
//   - All exhibiting similar request patterns
type AccountClusterDetector struct {
	keyProfiles map[string]*keyProfile
	mu          sync.RWMutex
}

type keyProfile struct {
	keyID            string
	promptStructures map[string]int // structure hash → count
	sourceIPs        map[string]bool
	endpoints        map[string]int
	requestCount     int
	firstSeen        time.Time
	lastSeen         time.Time
}

// NewAccountClusterDetector creates a detector for coordinated account clusters.
func NewAccountClusterDetector() *AccountClusterDetector {
	return &AccountClusterDetector{
		keyProfiles: make(map[string]*keyProfile),
	}
}

// ClusterResult indicates whether keys form a coordinated cluster.
type ClusterResult struct {
	ClusterKeys    []string
	ClusterSize    int
	IsCluster      bool
	Confidence     float64
	SharedIPs      []string
	SharedPatterns float64
	Flags          []string
}

// RecordKeyActivity records activity for a key for clustering analysis.
func (d *AccountClusterDetector) RecordKeyActivity(keyID, promptStructure, sourceIP, endpoint string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	profile, ok := d.keyProfiles[keyID]
	if !ok {
		profile = &keyProfile{
			keyID:            keyID,
			promptStructures: make(map[string]int),
			sourceIPs:        make(map[string]bool),
			endpoints:        make(map[string]int),
			firstSeen:        time.Now(),
		}
		d.keyProfiles[keyID] = profile
	}

	now := time.Now()
	profile.lastSeen = now
	profile.requestCount++

	if promptStructure != "" {
		profile.promptStructures[promptStructure]++
	}
	if sourceIP != "" {
		profile.sourceIPs[sourceIP] = true
	}
	if endpoint != "" {
		profile.endpoints[endpoint]++
	}
}

// DetectClusters identifies groups of keys with similar behavioral profiles.
func (d *AccountClusterDetector) DetectClusters() []ClusterResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Build similarity graph
	type keySim struct {
		key    string
		sim    float64
		shared []string
	}

	// For each pair of keys, compute similarity
	clusters := []ClusterResult{}
	processed := make(map[string]bool)

	keys := make([]string, 0, len(d.keyProfiles))
	for k := range d.keyProfiles {
		keys = append(keys, k)
	}

	for i, keyA := range keys {
		if processed[keyA] {
			continue
		}
		cluster := []string{keyA}
		sharedIPs := []string{}

		for j := i + 1; j < len(keys); j++ {
			keyB := keys[j]
			if processed[keyB] {
				continue
			}

			profA := d.keyProfiles[keyA]
			profB := d.keyProfiles[keyB]

			// Check shared IPs
			sharedIPCount := 0
			for ip := range profA.sourceIPs {
				if profB.sourceIPs[ip] {
					sharedIPCount++
					sharedIPs = append(sharedIPs, ip)
				}
			}

			// Check shared prompt structures
			sharedPatterns := 0
			for hash := range profA.promptStructures {
				if _, ok := profB.promptStructures[hash]; ok {
					sharedPatterns++
				}
			}

			// Similarity score: shared IPs + shared patterns
			ipSimilarity := 0.0
			if len(profA.sourceIPs) > 0 && len(profB.sourceIPs) > 0 {
				ipSimilarity = float64(sharedIPCount) / math.Max(float64(len(profA.sourceIPs)), float64(len(profB.sourceIPs)))
			}

			patternSimilarity := 0.0
			maxPatterns := math.Max(float64(len(profA.promptStructures)), float64(len(profB.promptStructures)))
			if maxPatterns > 0 {
				patternSimilarity = float64(sharedPatterns) / maxPatterns
			}

			overallSim := ipSimilarity*0.5 + patternSimilarity*0.5
			if overallSim > 0.7 {
				cluster = append(cluster, keyB)
				processed[keyB] = true
			}
		}

		if len(cluster) > 1 {
			processed[keyA] = true
			confidence := 0.0
			if len(cluster) >= 10 {
				confidence = 0.9
			} else if len(cluster) >= 5 {
				confidence = 0.75
			} else if len(cluster) >= 3 {
				confidence = 0.6
			} else {
				confidence = 0.5
			}

			clusters = append(clusters, ClusterResult{
				ClusterKeys:    cluster,
				ClusterSize:    len(cluster),
				IsCluster:      len(cluster) >= 3,
				Confidence:     confidence,
				SharedIPs:      sharedIPs,
				SharedPatterns: patternSimilarity(float64(len(cluster))),
				Flags:          []string{"coordinated_accounts", "behavioral_similarity"},
			})
		}
	}

	return clusters
}

// GetKeyCount returns the total number of tracked keys.
func (d *AccountClusterDetector) GetKeyCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.keyProfiles)
}

// =========================================================================
// GAP-DIST5: Stolen Key Detection (Behavioral Indicators)
// =========================================================================

// StolenKeyDetector identifies likely-stolen API keys through behavioral
// anomalies that differ from normal usage patterns.
//
// Indicators:
//   - Key used from new geographic region (geo-velocity check)
//   - Key used from datacenter/proxy IP (GAP-DIST2 integration)
//   - Key volume spike + new endpoint access (unusual for legitimate user)
//   - Key used concurrently from multiple IPs (impossible travel)
type StolenKeyDetector struct {
	keyHistory  map[string]*keyLocationHistory
	proxyDetect *ProxyServiceDetector
	mu          sync.RWMutex
}

type keyLocationHistory struct {
	keyID        string
	ips          map[string]time.Time // IP → first-seen
	regions      map[string]int       // region → count
	lastIP       string
	lastSeen     time.Time
	requestCount int
}

// NewStolenKeyDetector creates a detector for stolen key indicators.
func NewStolenKeyDetector(proxyDetect *ProxyServiceDetector) *StolenKeyDetector {
	return &StolenKeyDetector{
		keyHistory:  make(map[string]*keyLocationHistory),
		proxyDetect: proxyDetect,
	}
}

// StolenKeyResult indicates whether a key is likely stolen.
type StolenKeyResult struct {
	KeyID          string
	IsLikelyStolen bool
	Confidence     float64
	Flags          []string
	Details        []string
}

// RecordKeyUse records a key usage event for stolen-key analysis.
func (d *StolenKeyDetector) RecordKeyUse(keyID, sourceIP string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	hist, ok := d.keyHistory[keyID]
	if !ok {
		hist = &keyLocationHistory{
			keyID:   keyID,
			ips:     make(map[string]time.Time),
			regions: make(map[string]int),
		}
		d.keyHistory[keyID] = hist
	}

	now := time.Now()
	if _, exists := hist.ips[sourceIP]; !exists {
		hist.ips[sourceIP] = now
	}
	hist.lastIP = sourceIP
	hist.lastSeen = now
	hist.requestCount++
}

// CheckKey evaluates whether a key shows stolen-key indicators.
func (d *StolenKeyDetector) CheckKey(keyID, sourceIP string) StolenKeyResult {
	d.mu.RLock()
	hist, ok := d.keyHistory[keyID]
	d.mu.RUnlock()

	result := StolenKeyResult{KeyID: keyID}
	if !ok || hist.requestCount < 5 {
		return result
	}

	// Factor 1: Key used from datacenter/proxy IP
	if d.proxyDetect != nil {
		proxyResult := d.proxyDetect.CheckIP(sourceIP)
		if proxyResult.IsProxy {
			result.Confidence += 0.45
			result.Flags = append(result.Flags, "datacenter_ip_usage")
			result.Details = append(result.Details, "Key used from datacenter/proxy range: "+sourceIP)
		}
	}

	// Factor 2: Impossible travel (key used from many IPs in short time)
	if len(hist.ips) > 5 {
		result.Confidence += 0.4
		result.Flags = append(result.Flags, "excessive_ip_diversity")
		result.Details = append(result.Details, "Key used from multiple unique IPs")
	}

	// Factor 3: Rapid IP rotation (new IP within last 5 minutes of previous)
	if hist.lastIP != "" && hist.lastIP != sourceIP {
		lastSeenTime := hist.ips[hist.lastIP]
		if !lastSeenTime.IsZero() && time.Since(lastSeenTime) < 5*time.Minute {
			result.Confidence += 0.25
			result.Flags = append(result.Flags, "rapid_ip_rotation")
			result.Details = append(result.Details, "IP changed within 5 minutes (impossible travel)")
		}
	}

	// Factor 4: Geo-velocity — key moved from residential to datacenter
	if d.proxyDetect != nil {
		proxyResult := d.proxyDetect.CheckIP(sourceIP)
		if proxyResult.IsProxy {
			// Check if key previously had residential IPs
			hasResidential := false
			for ip := range hist.ips {
				if ip != sourceIP && !d.proxyDetect.CheckIP(ip).IsProxy {
					hasResidential = true
					break
				}
			}
			if hasResidential {
				result.Confidence += 0.2
				result.Flags = append(result.Flags, "geo_velocity_shift")
				result.Details = append(result.Details, "Key shifted from residential to datacenter IP")
			}
		}
	}

	if result.Confidence > 1.0 {
		result.Confidence = 1.0
	}

	result.IsLikelyStolen = result.Confidence >= 0.6

	return result
}

// GetKeyIPCount returns the number of unique IPs a key has been used from.
func (d *StolenKeyDetector) GetKeyIPCount(keyID string) int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if hist, ok := d.keyHistory[keyID]; ok {
		return len(hist.ips)
	}
	return 0
}

// CleanupExpired removes key histories older than 24 hours.
func (d *StolenKeyDetector) CleanupExpired() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	removed := 0
	for keyID, hist := range d.keyHistory {
		if now.Sub(hist.lastSeen) > 24*time.Hour {
			delete(d.keyHistory, keyID)
			removed++
		}
	}
	return removed
}

// patternSimilarity helper
func patternSimilarity(clusterSize float64) float64 {
	if clusterSize <= 1 {
		return 0
	}
	return math.Min(1.0, clusterSize/20)
}
