// SPDX-License-Identifier: Apache-2.0
// Package anomaly provides statistical anomaly detection for AegisGate security platform.
//
// This package implements lightweight, Go-native anomaly detection methods to enhance
// pattern-based security scanning. It is designed to be fast (< 1ms P99), configurable,
// and integration-ready with existing AegisGate packages.
//
// # Features
//
//   - Shannon entropy analysis for detecting high-randomness content (secrets, tokens)
//   - Character frequency distribution analysis for identifying unusual patterns
//   - Token structure classification for known secret formats
//   - Combined anomaly scoring with configurable weights and thresholds
//
// # Integration
//
// The package integrates with:
//
//   - pkg/response: Augments response guard scanning with anomaly scores
//   - pkg/scanner: Enhances secret detection to catch encoded/obfuscated secrets
//   - pkg/mcpserver: Provides session-level behavioral anomaly detection
//
// # Design Principles
//
//   - Pure Go, no external dependencies
//   - Fail-closed: errors default to pass-through, never block
//   - Immutable analysis: stateless where possible
//   - Streaming: process data without loading entire payloads
//   - Benchmark-first: all algorithms target < 1ms processing
//
// # Example Usage
//
//	config := anomaly.DefaultConfig()
//	score := anomaly.ScoreToken("sk-live-abc123xyz789", config.Scoring)
//
//	if score.IsAnomalous {
//	    log.Info("anomaly_detected",
//	        "score", score.Total,
//	        "flags", score.Flags,
//	    )
//	}
package anomaly
