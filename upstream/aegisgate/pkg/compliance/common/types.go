// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package common

// FrameworkConfig holds framework configuration
type FrameworkConfig struct {
	Name    string
	Version string
	Enabled bool
}

// TierInfo contains tier metadata
type TierInfo struct {
	Name        string
	Pricing     string
	Description string
}

// PricingInfo contains pricing details
type PricingInfo struct {
	Tier        string
	MonthlyCost int
	Description string
	Features    []string
}

// TechniqueFinding represents a technique check result
type TechniqueFinding struct {
	ID          string
	Name        string
	Tactic      string
	Severity    Severity
	Status      string
	Description string
}

// Findings is a collection of Finding
type Findings struct {
	Framework       string
	Version         string
	Timestamp       interface{} // time.Time
	Status          string
	Techniques      []TechniqueFinding
	Recommendations []string
}

// ITierManager interface for tier checking
type ITierManager interface {
	GetCurrentTier() string
	ValidateLicense() bool
}
