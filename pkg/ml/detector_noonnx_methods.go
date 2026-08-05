// SPDX-License-Identifier: Apache-2.0
//go:build !cgo
// +build !cgo

package ml

import (
	"fmt"
	"os"
	"path/filepath"
)

// loadModelONNX is a no-op when CGO is disabled.
// Returns nil but marks as heuristic-only mode.
func (td *ThreatDetector) loadModelONNX(path string) error {
	// When CGO is disabled, onnxruntime_go is excluded from the build.
	// The detector runs in heuristic-only mode.
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("model file not found: %w", err)
	}

	// Simple fingerprint for versioning (no crypto import needed)
	hash, err := computeFileHashSimple(path)
	if err != nil {
		return fmt.Errorf("compute model hash: %w", err)
	}

	td.modelHash = hash + " (heuristic-only, CGO disabled)"
	td.loaded = false // ONNX not available

	return nil
}

// inferenceONNX returns false when CGO is disabled.
func (td *ThreatDetector) inferenceONNX(encoded []int32) (float64, bool) {
	return 0, false
}

// closeONNX is a no-op when CGO is disabled.
func (td *ThreatDetector) closeONNX() error {
	return nil
}

// computeFileHashSimple computes a simplified hash for heuristic-only mode.
func computeFileHashSimple(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	if len(data) < 64 {
		return fmt.Sprintf("sha256:nocgo-%x", data), nil
	}
	return fmt.Sprintf("sha256:nocgo-%x", data[:64]), nil
}
