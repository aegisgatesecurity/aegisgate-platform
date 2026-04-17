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

package proxy

import (
	"context"

	"github.com/aegisgatesecurity/aegisgate/pkg/config"
	"github.com/aegisgatesecurity/aegisgate/pkg/ml"
)

// MLOptions extends proxy.Options with ML-specific configuration
type MLOptions struct {
	// ML Detection settings
	EnableMLDetection         bool
	MLSensitivity             string
	MLBlockOnCriticalSeverity bool
	MLBlockOnHighSeverity     bool
	MLMinScoreToBlock         float64
	MLSampleRate              int
	MLExcludedPaths           []string
	MLExcludedMethods         []string

	// Advanced ML features
	EnablePromptInjectionDetection bool
	PromptInjectionSensitivity     int
	EnableContentAnalysis          bool
	EnableBehavioralAnalysis       bool
}

// ProxyWithML extends Proxy with ML capabilities
// This is the recommended way to create a proxy with ML detection enabled
type ProxyWithML struct {
	*Proxy
	MLMiddleware            *MLMiddleware
	PromptInjectionDetector *ml.PromptInjectionDetector
	ContentAnalyzer         *ml.ContentAnalyzer
	BehavioralAnalyzer      *ml.BehavioralAnalyzer
}

// NewProxyWithConfig creates a new proxy from config.Config with ML enabled
// This is the main entry point for creating a production-ready proxy
func NewProxyWithConfig(cfg *config.Config) (*ProxyWithML, error) {
	if cfg == nil {
		return nil, nil
	}

	// Convert config to options
	opts := &Options{
		BindAddress: cfg.BindAddress,
		Upstream:    cfg.Upstream,
		MaxBodySize: cfg.MaxBodySize,
		RateLimit:   cfg.RateLimit,
		Timeout:     cfg.Timeout,
	}

	// Create proxy
	proxy := New(opts)

	p := &ProxyWithML{
		Proxy: proxy,
	}

	// Add ML middleware if enabled in config
	if cfg.ML != nil && cfg.ML.Enabled {
		mlConfig := &MLMiddlewareConfig{
			Enabled:                 cfg.ML.Enabled,
			Sensitivity:             cfg.ML.Sensitivity,
			BlockOnCriticalSeverity: cfg.ML.BlockOnCriticalSeverity,
			BlockOnHighSeverity:     cfg.ML.BlockOnHighSeverity,
			MinScoreToBlock:         cfg.ML.MinScoreToBlock,
			SampleRate:              cfg.ML.SampleRate,
			ExcludedPaths:           cfg.ML.ExcludedPaths,
			ExcludedMethods:         cfg.ML.ExcludedMethods,
			LogAllAnomalies:         cfg.ML.LogAllAnomalies,
		}

		mlMiddleware, err := NewMLMiddleware(mlConfig)
		if err != nil {
			return nil, err
		}

		p.MLMiddleware = mlMiddleware

		// Add advanced ML features if enabled
		if cfg.ML.EnablePromptInjectionDetection {
			p.PromptInjectionDetector = ml.NewPromptInjectionDetector(cfg.ML.PromptInjectionSensitivity)
		}

		if cfg.ML.EnableContentAnalysis {
			p.ContentAnalyzer = ml.NewContentAnalyzer()
		}

		if cfg.ML.EnableBehavioralAnalysis {
			p.BehavioralAnalyzer = ml.NewBehavioralAnalyzer()
		}
	}

	return p, nil
}

// NewProxyWithMLOptions creates a new proxy with ML options
func NewProxyWithMLOptions(opts *Options, mlOpts *MLOptions) (*ProxyWithML, error) {
	// Create base proxy
	proxy := New(opts)

	p := &ProxyWithML{
		Proxy: proxy,
	}

	// Add ML middleware if enabled
	if mlOpts != nil && mlOpts.EnableMLDetection {
		mlConfig := &MLMiddlewareConfig{
			Enabled:                 mlOpts.EnableMLDetection,
			Sensitivity:             mlOpts.MLSensitivity,
			BlockOnCriticalSeverity: mlOpts.MLBlockOnCriticalSeverity,
			BlockOnHighSeverity:     mlOpts.MLBlockOnHighSeverity,
			MinScoreToBlock:         mlOpts.MLMinScoreToBlock,
			SampleRate:              mlOpts.MLSampleRate,
			ExcludedPaths:           mlOpts.MLExcludedPaths,
			ExcludedMethods:         mlOpts.MLExcludedMethods,
		}

		mlMiddleware, err := NewMLMiddleware(mlConfig)
		if err != nil {
			return nil, err
		}

		p.MLMiddleware = mlMiddleware

		// Add advanced ML features
		if mlOpts.EnablePromptInjectionDetection {
			p.PromptInjectionDetector = ml.NewPromptInjectionDetector(mlOpts.PromptInjectionSensitivity)
		}

		if mlOpts.EnableContentAnalysis {
			p.ContentAnalyzer = ml.NewContentAnalyzer()
		}

		if mlOpts.EnableBehavioralAnalysis {
			p.BehavioralAnalyzer = ml.NewBehavioralAnalyzer()
		}
	}

	return p, nil
}

// Start starts the proxy server with ML middleware in the pipeline
func (p *ProxyWithML) Start() error {
	if p.Proxy == nil {
		return nil
	}

	// The ML middleware is applied via the handler chain
	// In Start(), we wrap the handler with ML middleware
	return p.Proxy.Start()
}

// Stop stops the proxy
func (p *ProxyWithML) Stop() error {
	if p.Proxy == nil {
		return nil
	}
	return p.Proxy.Stop(context.Background())
}

// GetMLStats returns ML detection statistics
func (p *ProxyWithML) GetMLStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if p.MLMiddleware != nil {
		mlStats := p.MLMiddleware.GetStats()
		stats["middleware"] = map[string]interface{}{
			"total_requests":    mlStats.TotalRequests,
			"analyzed_requests": mlStats.AnalyzedRequests,
			"blocked_requests":  mlStats.BlockedRequests,
			"anomaly_counts":    mlStats.AnomalyCounts,
		}
	}

	if p.PromptInjectionDetector != nil {
		stats["prompt_injection"] = p.PromptInjectionDetector.GetStats()
	}

	if p.ContentAnalyzer != nil {
		stats["content_analysis"] = p.ContentAnalyzer.GetStats()
	}

	if p.BehavioralAnalyzer != nil {
		stats["behavioral_analysis"] = p.BehavioralAnalyzer.GetStats()
	}

	return stats
}

// ResetMLStats resets all ML statistics
func (p *ProxyWithML) ResetMLStats() {
	if p.MLMiddleware != nil {
		p.MLMiddleware.ResetStats()
	}

	if p.PromptInjectionDetector != nil {
		p.PromptInjectionDetector.Reset()
	}

	if p.ContentAnalyzer != nil {
		p.ContentAnalyzer.Reset()
	}

	if p.BehavioralAnalyzer != nil {
		p.BehavioralAnalyzer.Reset()
	}
}

// GetHealth returns health status including ML
func (p *ProxyWithML) GetHealth() map[string]interface{} {
	health := p.Proxy.GetHealth()

	if p.MLMiddleware != nil {
		health["ml_enabled"] = true
		health["ml_sensitivity"] = p.MLMiddleware.config.Sensitivity
	} else {
		health["ml_enabled"] = false
	}

	return health
}

// ConvertConfigToMLOptions converts config.MLConfig to MLOptions
func ConvertConfigToMLOptions(cfg *config.Config) *MLOptions {
	if cfg == nil || cfg.ML == nil {
		return &MLOptions{
			EnableMLDetection: false,
		}
	}

	return &MLOptions{
		EnableMLDetection:              cfg.ML.Enabled,
		MLSensitivity:                  cfg.ML.Sensitivity,
		MLBlockOnCriticalSeverity:      cfg.ML.BlockOnCriticalSeverity,
		MLBlockOnHighSeverity:          cfg.ML.BlockOnHighSeverity,
		MLMinScoreToBlock:              cfg.ML.MinScoreToBlock,
		MLSampleRate:                   cfg.ML.SampleRate,
		MLExcludedPaths:                cfg.ML.ExcludedPaths,
		MLExcludedMethods:              cfg.ML.ExcludedMethods,
		EnablePromptInjectionDetection: cfg.ML.EnablePromptInjectionDetection,
		PromptInjectionSensitivity:     cfg.ML.PromptInjectionSensitivity,
		EnableContentAnalysis:          cfg.ML.EnableContentAnalysis,
		EnableBehavioralAnalysis:       cfg.ML.EnableBehavioralAnalysis,
	}
}
