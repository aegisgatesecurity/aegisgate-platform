// Package mcp - Model Context Protocol Server Implementation
// Based on MCP Specification 2024-11-05
package mcp

import (
	"encoding/json"
	"time"
)

const ProtocolVersion = "2024-11-05"
const JSONRPCVersion = "2.0"

const (
	ErrorParseError     = -32700
	ErrorInvalidRequest = -32600
	ErrorMethodNotFound = -32601
	ErrorInvalidParams  = -32602
	ErrorInternal       = -32603
)

type ServerInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

type ClientInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

type ServerCapabilities struct {
	Tools        *ToolCapabilities      `json:"tools,omitempty"`
	Resources    *ResourceCapabilities  `json:"resources,omitempty"`
	Prompts      *PromptCapabilities    `json:"prompts,omitempty"`
	Logging      *LoggingCapabilities   `json:"logging,omitempty"`
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

type ToolCapabilities struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type ResourceCapabilities struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

type PromptCapabilities struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type LoggingCapabilities struct{}

type ClientCapabilities struct {
	Roots       *RootsCapability       `json:"roots,omitempty"`
	Sampling    *SamplingCapability    `json:"sampling,omitempty"`
	Elicitation *ElicitationCapability `json:"elicitation,omitempty"`
}

type RootsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type SamplingCapability struct{}

type ElicitationCapability struct {
	Form *struct{} `json:"form,omitempty"`
	URL  *struct{} `json:"url,omitempty"`
}

type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

type CallToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

type ListResourcesResult struct {
	Resources []Resource `json:"resources"`
}

type ListPromptsResult struct {
	Prompts []Prompt `json:"prompts"`
}

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id,omitempty"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func NewServerInfo() ServerInfo {
	return ServerInfo{
		Name:        "aegisguard",
		Version:     "0.1.0",
		Description: "AI Agent Security Platform",
	}
}

func NewServerCapabilities() ServerCapabilities {
	return ServerCapabilities{
		Tools:     &ToolCapabilities{ListChanged: true},
		Resources: &ResourceCapabilities{Subscribe: true, ListChanged: true},
		Prompts:   &PromptCapabilities{ListChanged: true},
		Logging:   &LoggingCapabilities{},
	}
}

func NewInitializeResult() InitializeResult {
	return InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    NewServerCapabilities(),
		ServerInfo:      NewServerInfo(),
	}
}

func Now() time.Time {
	return time.Now()
}
