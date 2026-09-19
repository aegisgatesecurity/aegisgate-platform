// Copyright 2025 AegisGate Security
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package toolauth
//
// v4.5.0 Enhancement P2: Tool Call Chain Analysis
//
// chain_analyzer.go analyzes sequences of tool calls within a session to
// detect chained attack patterns. It extends the Tool Authorization Matrix
// by correlating individual tool authorizations across a conversation,
// identifying:
//   - Privilege escalation chains (low-risk tool → high-risk tool)
//   - Data exfiltration chains (read sensitive → write external)
//   - Reconnaissance-to-exploitation chains (scan → exploit)
//   - Unusual sequencing that deviates from expected tool usage patterns
//
// The analyzer operates on a sliding window of tool call records and
// produces a chain risk assessment that can augment the per-call decision.

package toolauth

import (
	"strings"
	"sync"
	"time"
)

// ChainWindow is the maximum number of tool calls retained for chain analysis.
const ChainWindow = 20

// ChainTTL is the default time-to-live for inactive chain tracking.
const ChainTTL = 30 * time.Minute

// ChainEntry records a single tool call within a chain.
type ChainEntry struct {
	Timestamp time.Time
	ToolName  string
	RiskLevel RiskLevel
	Decision  string // "allow", "deny", "require_approval"
	DataType  string // "read", "write", "execute", "network"
	Target    string // target resource or endpoint
}

// ChainResult is the analysis output for a tool call chain.
type ChainResult struct {
	SessionID       string
	CallCount       int
	EscalationChain bool
	ExfilChain      bool
	ReconChain      bool
	OverallRisk     RiskLevel
	Flags           []string
}

// ChainAnalyzer tracks tool call sequences and detects chained attack patterns.
type ChainAnalyzer struct {
	chains map[string][]ChainEntry
	mu     sync.RWMutex
	window int
	ttl    time.Duration
}

// NewChainAnalyzer creates a new ChainAnalyzer with default configuration.
func NewChainAnalyzer() *ChainAnalyzer {
	return &ChainAnalyzer{
		chains: make(map[string][]ChainEntry),
		window: ChainWindow,
		ttl:    ChainTTL,
	}
}

// RecordCall adds a tool call to the session's chain tracking.
func (ca *ChainAnalyzer) RecordCall(sessionID string, entry ChainEntry) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	chain := ca.chains[sessionID]
	chain = append(chain, entry)
	if len(chain) > ca.window {
		chain = chain[len(chain)-ca.window:]
	}
	ca.chains[sessionID] = chain
}

// AnalyzeChain evaluates the session's tool call history for chained patterns.
func (ca *ChainAnalyzer) AnalyzeChain(sessionID string) ChainResult {
	ca.mu.RLock()
	chain := ca.chains[sessionID]
	ca.mu.RUnlock()

	result := ChainResult{
		SessionID:   sessionID,
		CallCount:   len(chain),
		OverallRisk: RiskLevelNone,
	}

	if len(chain) < 2 {
		return result
	}

	result.EscalationChain = ca.detectEscalationChain(chain)
	result.ExfilChain = ca.detectExfilChain(chain)
	result.ReconChain = ca.detectReconChain(chain)

	// Aggregate overall risk
	maxRisk := RiskLevelNone
	for _, entry := range chain {
		if entry.RiskLevel > maxRisk {
			maxRisk = entry.RiskLevel
		}
	}

	if result.EscalationChain || result.ExfilChain {
		result.OverallRisk = RiskLevelHigh
		if maxRisk >= RiskLevelCritical {
			result.OverallRisk = RiskLevelCritical
		}
	} else if result.ReconChain {
		result.OverallRisk = RiskLevelMedium
	} else if maxRisk > RiskLevelNone {
		result.OverallRisk = maxRisk
	}

	if result.EscalationChain {
		result.Flags = append(result.Flags, "privilege_escalation_chain")
	}
	if result.ExfilChain {
		result.Flags = append(result.Flags, "data_exfiltration_chain")
	}
	if result.ReconChain {
		result.Flags = append(result.Flags, "recon_to_exploit_chain")
	}

	return result
}

// detectEscalationChain identifies sequences where risk levels increase
// from low to high/critical across consecutive tool calls.
func (ca *ChainAnalyzer) detectEscalationChain(chain []ChainEntry) bool {
	escalating := 0
	for i := 1; i < len(chain); i++ {
		if chain[i].RiskLevel > chain[i-1].RiskLevel {
			escalating++
		}
	}
	// If more than half the transitions are escalating, flag it
	return escalating > (len(chain)-1)/2
}

// detectExfilChain identifies read-then-network sequences that could
// indicate data exfiltration: sensitive read followed by external write/network.
func (ca *ChainAnalyzer) detectExfilChain(chain []ChainEntry) bool {
	for i, entry := range chain {
		if entry.DataType == "read" && entry.RiskLevel >= RiskLevelMedium {
			// Look for a subsequent network/write call
			for j := i + 1; j < len(chain); j++ {
				if chain[j].DataType == "network" || chain[j].DataType == "write" {
					return true
				}
			}
		}
	}
	return false
}

// detectReconChain identifies scan-then-execute patterns where
// reconnaissance tools are followed by exploitation tools.
// Uses prefix matching to catch tools with similar names (e.g.,
// "browse_directory" matches "browse", "scan_folder" matches "scan").
func (ca *ChainAnalyzer) detectReconChain(chain []ChainEntry) bool {
	// Recon prefix patterns — match tool names that start with these prefixes.
	// This is more robust than exact matching because MCP servers may expose
	// tools with variations like "list_directory", "browse_files", "scan_env".
	reconPrefixes := []string{
		"list", "read", "get", "browse", "scan", "enumerate",
		"discover", "inspect", "probe", "explore", "survey",
		"reconnoiter", "fetch", "query", "search",
	}

	// Exact-match recon tool names (for tools that don't follow the prefix
	// convention but are clearly reconnaissance).
	reconExact := map[string]bool{
		"get_env":     true,
		"read_config": true,
	}

	for i, entry := range chain {
		if isReconTool(entry.ToolName, reconPrefixes, reconExact) {
			for j := i + 1; j < len(chain); j++ {
				if chain[j].DataType == "execute" && chain[j].RiskLevel >= RiskLevelHigh {
					return true
				}
			}
		}
	}
	return false
}

// isReconTool checks whether a tool name matches a recon prefix or exact name.
func isReconTool(toolName string, prefixes []string, exact map[string]bool) bool {
	if exact[toolName] {
		return true
	}
	lower := strings.ToLower(toolName)
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// CleanupExpired removes chain tracking data that has exceeded the TTL.
func (ca *ChainAnalyzer) CleanupExpired() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	now := time.Now()
	removed := 0
	for id, chain := range ca.chains {
		if len(chain) > 0 && now.Sub(chain[len(chain)-1].Timestamp) > ca.ttl {
			delete(ca.chains, id)
			removed++
		}
	}
	return removed
}
