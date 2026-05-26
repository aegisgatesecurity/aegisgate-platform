// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Protocol Types
// =========================================================================
//
// ACP protocol message types aligned with the official ACP specification.
// Ref: https://agentclientprotocol.com/
//
// =========================================================================

package acp

import (
	"time"
)

// ============================================================================
// ACP Message Types (from ACP Specification)
// ============================================================================

// ACPMessage represents a generic ACP message
type ACPMessage struct {
	ID     string                 `json:"id,omitempty"`
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
	Result interface{}            `json:"result,omitempty"`
	Error  *ACPError              `json:"error,omitempty"`
	_meta  map[string]interface{} `json:"_meta,omitempty"`
}

// AgentRequest represents a request from an agent
type AgentRequest struct {
	ID     string                 `json:"id"`
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params"`
}

// AgentResponse represents a response from an agent
type AgentResponse struct {
	ID     string      `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  *ACPError   `json:"error,omitempty"`
}

// ClientRequest represents a request from a client (code editor)
type ClientRequest struct {
	ID     string                 `json:"id"`
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params"`
}

// ClientResponse represents a response from a client
type ClientResponse struct {
	ID     string      `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  *ACPError   `json:"error,omitempty"`
}

// ============================================================================
// ACP Error Types
// ============================================================================

// ACPError represents an ACP protocol error
type ACPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Common ACP error codes
const (
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603
	ErrorCodeUnauthorized   = 401
	ErrorCodeForbidden      = 403
	ErrorCodeRateLimited    = 429
)

// ============================================================================
// ACP Capabilities
// ============================================================================

// AgentCapabilities represents agent capabilities advertised during init
type AgentCapabilities struct {
	Auth           *AgentAuthCapabilities  `json:"auth,omitempty"`
	Streaming      bool                    `json:"streaming,omitempty"`
	BinaryMessages bool                    `json:"binaryMessages,omitempty"`
	Environ        bool                    `json:"environ,omitempty"`
	Terminal       *TerminalCapabilities   `json:"terminal,omitempty"`
	FileSystem     *FileSystemCapabilities `json:"fs,omitempty"`
	Http           *HttpCapabilities       `json:"http,omitempty"`
}

// ClientCapabilities represents client capabilities advertised during init
type ClientCapabilities struct {
	Auth           *ClientAuthCapabilities `json:"auth,omitempty"`
	Streaming      bool                    `json:"streaming,omitempty"`
	BinaryMessages bool                    `json:"binaryMessages,omitempty"`
	Terminal       *TerminalCapabilities   `json:"terminal,omitempty"`
	FileSystem     *FileSystemCapabilities `json:"fs,omitempty"`
	Http           *HttpCapabilities       `json:"http,omitempty"`
}

// AgentAuthCapabilities represents agent authentication capabilities
type AgentAuthCapabilities struct {
	Methods []AuthMethod `json:"methods"`
}

// ClientAuthCapabilities represents client authentication capabilities
type ClientAuthCapabilities struct {
	Methods []AuthMethod `json:"methods"`
}

// AuthMethod represents an authentication method
type AuthMethod struct {
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
}

// ============================================================================
// ACP Terminal Capabilities
// ============================================================================

// TerminalCapabilities represents terminal capabilities
type TerminalCapabilities struct {
	Persistence bool  `json:"persist,omitempty"`
	Env         bool  `json:"env,omitempty"`
	UserJoin    bool  `json:"userJoined,omitempty"`
	Readline    bool  `json:"readline,omitempty"`
	Links       bool  `json:"links,omitempty"`
	Signals     bool  `json:"signals,omitempty"`
	Deadline    int64 `json:"deadline,omitempty"`
}

// ============================================================================
// ACP FileSystem Capabilities
// ============================================================================

// FileSystemCapabilities represents filesystem capabilities
type FileSystemCapabilities struct {
	Read               bool     `json:"read,omitempty"`
	ReadEnv            bool     `json:"readEnv,omitempty"`
	ReadPath           []string `json:"readPath,omitempty"`
	Write              bool     `json:"write,omitempty"`
	WritePath          []string `json:"writePath,omitempty"`
	Mkdir              bool     `json:"mkdir,omitempty"`
	TemporaryDirectory string   `json:"temporaryDirectory,omitempty"`
	TempDir            bool     `json:"tempDir,omitempty"`
}

// ============================================================================
// ACP HTTP Capabilities
// ============================================================================

// HttpCapabilities represents HTTP capabilities
type HttpCapabilities struct {
	Enabled   bool   `json:"enabled,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	Timeout   int64  `json:"timeout,omitempty"`
}

// ============================================================================
// ACP Initialize Messages
// ============================================================================

// InitializeRequest represents the init request from client
type InitializeRequest struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities,omitempty"`
	Auth            *AuthCredentials   `json:"auth,omitempty"`
}

// InitializeResponse represents the init response from agent
type InitializeResponse struct {
	ProtocolVersion string                `json:"protocolVersion"`
	Capabilities    AgentCapabilities     `json:"capabilities"`
	Auth            *AuthenticateResponse `json:"auth,omitempty"`
}

// ============================================================================
// ACP Auth Messages
// ============================================================================

// AuthenticateRequest represents authentication request
type AuthenticateRequest struct {
	MethodID    string            `json:"methodId"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

// AuthenticateResponse represents authentication response
type AuthenticateResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

// AuthCredentials represents authentication credentials
type AuthCredentials struct {
	Token  string `json:"token,omitempty"`
	Method string `json:"method,omitempty"`
}

// ============================================================================
// ACP Session Management
// ============================================================================

// SessionInfo represents an ACP session
type SessionInfo struct {
	ID           string             `json:"id"`
	CreatedAt    time.Time          `json:"createdAt"`
	AuthToken    string             `json:"authToken,omitempty"`
	Capabilities ClientCapabilities `json:"capabilities,omitempty"`
}

// ============================================================================
// ACP Notification Types
// ============================================================================

// SessionNotification represents a session-related notification
type SessionNotification struct {
	Type    string `json:"type"`
	Session string `json:"session"`
	Message string `json:"message,omitempty"`
}

// TerminalOutputNotification represents terminal output
type TerminalOutputNotification struct {
	TerminalID string `json:"terminalId"`
	Chunk      string `json:"chunk"`
	Overflow   bool   `json:"overflow,omitempty"`
}
