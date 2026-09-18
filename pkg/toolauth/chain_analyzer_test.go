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

package toolauth

import (
	"testing"
	"time"
)

func TestNewChainAnalyzer(t *testing.T) {
	ca := NewChainAnalyzer()
	if ca == nil {
		t.Fatal("NewChainAnalyzer returned nil")
	}
	if ca.window != ChainWindow {
		t.Errorf("expected window=%d, got %d", ChainWindow, ca.window)
	}
}

func TestRecordCall_CreatesChain(t *testing.T) {
	ca := NewChainAnalyzer()
	ca.RecordCall("sess-1", ChainEntry{
		ToolName:  "read_file",
		RiskLevel: RiskLevelLow,
		DataType:  "read",
	})

	ca.mu.RLock()
	chain, ok := ca.chains["sess-1"]
	ca.mu.RUnlock()
	if !ok || len(chain) != 1 {
		t.Fatalf("chain not created or wrong length: %v", chain)
	}
}

func TestRecordCall_WindowTrimming(t *testing.T) {
	ca := NewChainAnalyzer()
	ca.window = 3

	for i := 0; i < 5; i++ {
		ca.RecordCall("sess-trim", ChainEntry{
			ToolName:  "tool",
			RiskLevel: RiskLevelLow,
		})
	}

	ca.mu.RLock()
	chain := ca.chains["sess-trim"]
	ca.mu.RUnlock()
	if len(chain) != 3 {
		t.Errorf("expected 3 entries after trim, got %d", len(chain))
	}
}

func TestAnalyzeChain_NoSession(t *testing.T) {
	ca := NewChainAnalyzer()
	result := ca.AnalyzeChain("nonexistent")
	if result.OverallRisk != RiskLevelNone {
		t.Errorf("expected RiskLevelNone, got %d", result.OverallRisk)
	}
}

func TestAnalyzeChain_SingleCall(t *testing.T) {
	ca := NewChainAnalyzer()
	ca.RecordCall("sess-single", ChainEntry{RiskLevel: RiskLevelHigh})
	result := ca.AnalyzeChain("sess-single")
	if result.CallCount != 1 {
		t.Errorf("expected 1 call, got %d", result.CallCount)
	}
	if result.OverallRisk != RiskLevelNone {
		t.Errorf("expected RiskLevelNone for single call, got %d", result.OverallRisk)
	}
}

func TestAnalyzeChain_EscalationChain(t *testing.T) {
	ca := NewChainAnalyzer()
	levels := []RiskLevel{RiskLevelLow, RiskLevelMedium, RiskLevelHigh, RiskLevelCritical}
	for _, lvl := range levels {
		ca.RecordCall("sess-escalate", ChainEntry{
			RiskLevel: lvl,
			DataType:  "execute",
		})
	}
	result := ca.AnalyzeChain("sess-escalate")
	if !result.EscalationChain {
		t.Error("expected escalation chain to be detected")
	}
	if result.OverallRisk < RiskLevelHigh {
		t.Errorf("expected High+ risk, got %d", result.OverallRisk)
	}
}

func TestAnalyzeChain_ExfilChain(t *testing.T) {
	ca := NewChainAnalyzer()
	ca.RecordCall("sess-exfil", ChainEntry{
		ToolName:  "read_secrets",
		RiskLevel: RiskLevelHigh,
		DataType:  "read",
	})
	ca.RecordCall("sess-exfil", ChainEntry{
		ToolName:  "http_post",
		RiskLevel: RiskLevelMedium,
		DataType:  "network",
	})
	result := ca.AnalyzeChain("sess-exfil")
	if !result.ExfilChain {
		t.Error("expected exfil chain to be detected")
	}
}

func TestAnalyzeChain_ReconChain(t *testing.T) {
	ca := NewChainAnalyzer()
	ca.RecordCall("sess-recon", ChainEntry{
		ToolName:  "enumerate",
		RiskLevel: RiskLevelLow,
		DataType:  "read",
	})
	ca.RecordCall("sess-recon", ChainEntry{
		ToolName:  "execute_payload",
		RiskLevel: RiskLevelCritical,
		DataType:  "execute",
	})
	result := ca.AnalyzeChain("sess-recon")
	if !result.ReconChain {
		t.Error("expected recon chain to be detected")
	}
}

func TestDetectEscalationChain_NotEscalating(t *testing.T) {
	ca := NewChainAnalyzer()
	chain := []ChainEntry{
		{RiskLevel: RiskLevelHigh},
		{RiskLevel: RiskLevelLow},
		{RiskLevel: RiskLevelNone},
	}
	if ca.detectEscalationChain(chain) {
		t.Error("expected no escalation for descending risk")
	}
}

func TestDetectExfilChain_NoMatch(t *testing.T) {
	ca := NewChainAnalyzer()
	chain := []ChainEntry{
		{DataType: "read", RiskLevel: RiskLevelLow},
		{DataType: "read", RiskLevel: RiskLevelLow},
	}
	if ca.detectExfilChain(chain) {
		t.Error("expected no exfil for read-only chain")
	}
}

func TestDetectReconChain_NoMatch(t *testing.T) {
	ca := NewChainAnalyzer()
	chain := []ChainEntry{
		{ToolName: "read_file", DataType: "read"},
		{ToolName: "read_file", DataType: "read"},
	}
	if ca.detectReconChain(chain) {
		t.Error("expected no recon for non-recon tools")
	}
}

func TestChainCleanupExpired(t *testing.T) {
	ca := NewChainAnalyzer()
	ca.ttl = 50 * time.Millisecond

	ca.RecordCall("sess-old", ChainEntry{RiskLevel: RiskLevelLow})
	time.Sleep(100 * time.Millisecond)
	ca.RecordCall("sess-new", ChainEntry{RiskLevel: RiskLevelLow})

	removed := ca.CleanupExpired()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
}
