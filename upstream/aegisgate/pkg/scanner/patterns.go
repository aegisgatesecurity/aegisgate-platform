// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package scanner

import (
	"regexp"
)

// Severity represents the risk level of a finding
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

// String returns the string representation of Severity
func (s Severity) String() string {
	switch s {
	case Info:
		return "Info"
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Critical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// Category represents the type of sensitive data detected
type Category string

const (
	CategoryPII           Category = "PII"
	CategoryCredential    Category = "Credential"
	CategoryFinancial     Category = "Financial"
	CategoryCryptographic Category = "Cryptographic"
	CategoryNetwork       Category = "Network"
)

// Pattern represents a detection pattern for sensitive data
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    Severity
	Category    Category
	Description string
}

// DefaultPatterns returns the complete set of detection patterns
// Note: Go's regexp package uses RE2 syntax which doesn't support negative lookahead
func DefaultPatterns() []*Pattern {
	return []*Pattern{
		// Credit Cards - Visa
		{
			Name:        "VisaCreditCard",
			Regex:       regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`),
			Severity:    Critical,
			Category:    CategoryFinancial,
			Description: "Visa credit card number detected",
		},
		// Credit Cards - Mastercard
		{
			Name:        "MastercardCreditCard",
			Regex:       regexp.MustCompile(`\b5[1-5][0-9]{14}\b`),
			Severity:    Critical,
			Category:    CategoryFinancial,
			Description: "Mastercard credit card number detected",
		},
		// Credit Cards - American Express
		{
			Name:        "AmexCreditCard",
			Regex:       regexp.MustCompile(`\b3[47][0-9]{13}\b`),
			Severity:    Critical,
			Category:    CategoryFinancial,
			Description: "American Express credit card number detected",
		},
		// US Social Security Number (basic format - Go RE2 doesn't support negative lookahead)
		{
			Name:        "USSSN",
			Regex:       regexp.MustCompile(`\b\d{3}-?\d{2}-?\d{4}\b`),
			Severity:    Critical,
			Category:    CategoryPII,
			Description: "US Social Security Number detected",
		},
		// AWS Access Key ID
		{
			Name:        "AWSAccessKeyID",
			Regex:       regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			Severity:    Critical,
			Category:    CategoryCredential,
			Description: "AWS Access Key ID detected",
		},
		// AWS Secret Access Key
		{
			Name:        "AWSSecretKey",
			Regex:       regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`),
			Severity:    Critical,
			Category:    CategoryCredential,
			Description: "Potential AWS Secret Access Key detected",
		},
		// GitHub Token (updated to match ghp_, gho_, ghs_ prefixes)
		{
			Name:        "GitHubToken",
			Regex:       regexp.MustCompile(`\bgh[pousr]_[a-zA-Z0-9]{36,}\b`),
			Severity:    Critical,
			Category:    CategoryCredential,
			Description: "GitHub token detected",
		},
		// Generic API Key
		{
			Name:        "GenericAPIKey",
			Regex:       regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)[:\s=]+['"]?[a-z0-9]{32,}['"]?`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "Generic API key detected",
		},
		// API Key (generic pattern)
		{
			Name:        "APIKey",
			Regex:       regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)(?::[\s]*|[\s]*=|[\s]+)['"]?[a-z0-9_]{10,}['"]?`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "API key detected",
		},
		// Password in body
		{
			Name:        "PasswordInBody",
			Regex:       regexp.MustCompile(`(?i)(?:password|pwd|pass)[:\s=]+['"]?[^\s]{4,}['"]?`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "Password found in request/response body",
		},
		// Private Key (RSA)
		{
			Name:        "RSAPrivateKey",
			Regex:       regexp.MustCompile(`-----BEGIN (?:RSA )?PRIVATE KEY-----`),
			Severity:    Critical,
			Category:    CategoryCryptographic,
			Description: "RSA private key detected",
		},
		// Private Key (EC)
		{
			Name:        "ECPrivateKey",
			Regex:       regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			Severity:    Critical,
			Category:    CategoryCryptographic,
			Description: "Elliptic Curve private key detected",
		},
		// Private Key (OpenSSH)
		{
			Name:        "OpenSSHPrivateKey",
			Regex:       regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			Severity:    Critical,
			Category:    CategoryCryptographic,
			Description: "OpenSSH private key detected",
		},
		// Private Key (DSA)
		{
			Name:        "DSAPrivateKey",
			Regex:       regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
			Severity:    Critical,
			Category:    CategoryCryptographic,
			Description: "DSA private key detected",
		},
		// Database Connection String (PostgreSQL)
		{
			Name:        "PostgreSQLConnectionString",
			Regex:       regexp.MustCompile(`(?i)postgresql://[^\s"']+`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "PostgreSQL connection string detected",
		},
		// Database Connection String (MySQL)
		{
			Name:        "MySQLConnectionString",
			Regex:       regexp.MustCompile(`(?i)mysql://[^\s"']+`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "MySQL connection string detected",
		},
		// Database Connection String (MongoDB)
		{
			Name:        "MongoDBConnectionString",
			Regex:       regexp.MustCompile(`(?i)mongodb(\+srv)?://[^\s"']+`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "MongoDB connection string detected",
		},
		// Database Connection String (Redis)
		{
			Name:        "RedisConnectionString",
			Regex:       regexp.MustCompile(`(?i)redis://[^\s"']+`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "Redis connection string detected",
		},
		// Database Connection String (SQLServer)
		{
			Name:        "SQLServerConnectionString",
			Regex:       regexp.MustCompile(`(?i)sqlserver://[^\s"']+`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "SQLServer connection string detected",
		},
		// Database Connection String (Oracle)
		{
			Name:        "OracleConnectionString",
			Regex:       regexp.MustCompile(`(?i)oracle://[^\s"']+`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "Oracle connection string detected",
		},
		// Email Address
		{
			Name:        "EmailAddress",
			Regex:       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			Severity:    Low,
			Category:    CategoryPII,
			Description: "Email address detected",
		},
		// Phone Number
		{
			Name:        "PhoneNumber",
			Regex:       regexp.MustCompile(`\b(?:\d{3}-?\d{4}|\d{3}-\d{3}-\d{4}|\(\d{3}\)\s?\d{3}-\d{4}|\d{3}\.\d{3}\.\d{4})\b`),
			Severity:    Medium,
			Category:    CategoryPII,
			Description: "Phone number detected",
		},
		// Internal IP Address (RFC1918)
		{
			Name:        "InternalIPAddress",
			Regex:       regexp.MustCompile(`\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b`),
			Severity:    Low,
			Category:    CategoryNetwork,
			Description: "Internal/RFC1918 IP address detected",
		},
		// Bearer Token
		{
			Name:        "BearerToken",
			Regex:       regexp.MustCompile(`\bBearer\s+[a-zA-Z0-9_\-\.]+`),
			Severity:    Medium,
			Category:    CategoryCredential,
			Description: "Bearer token detected",
		},
		// JWT Token
		{
			Name:        "JWTToken",
			Regex:       regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b`),
			Severity:    Medium,
			Category:    CategoryCredential,
			Description: "JSON Web Token (JWT) detected",
		},
		// Slack Token
		{
			Name:        "SlackToken",
			Regex:       regexp.MustCompile(`\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b`),
			Severity:    High,
			Category:    CategoryCredential,
			Description: "Slack token detected",
		},
	}
}

// ShouldBlock returns true if the severity level should trigger a block
func ShouldBlock(severity Severity) bool {
	return severity >= High
}
