// Package toolregistry - Tool registry for AI agent capabilities management
// Provides tool registration, metadata management, and discovery
package toolregistry

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Registry manages tool registrations and metadata
type Registry struct {
	mu          sync.RWMutex
	tools       map[string]*Tool
	categories  map[string][]string
	handlers    map[string]ToolHandler
	lastUpdated time.Time
}

// Tool represents a registered tool
type Tool struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Category      string                 `json:"category"`
	Parameters    []Parameter            `json:"parameters"`
	Handler       ToolHandler            `json:"-"`
	Enabled       bool                   `json:"enabled"`
	RiskLevel     int                    `json:"risk_level"` // 0-100
	RateLimit     *RateLimitConfig       `json:"rate_limit,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// Parameter defines a tool parameter
type Parameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"` // string, int, bool, array, object
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Min         *float64    `json:"min,omitempty"`
	Max         *float64    `json:"max,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
}

// RateLimitConfig holds rate limit settings for a tool
type RateLimitConfig struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	BurstSize         int     `json:"burst_size"`
}

// ToolHandler interface for tool execution
type ToolHandler interface {
	Execute(ctx context.Context, params map[string]interface{}) (interface{}, error)
	Validate(params map[string]interface{}) error
}

// DiscoveryResult represents tool search results
type DiscoveryResult struct {
	Tools       []*Tool
	TotalCount  int
	Query       string
	Category    string
}

// NewRegistry creates a new tool registry
func NewRegistry() *Registry {
	return &Registry{
		tools:       make(map[string]*Tool),
		categories:  make(map[string][]string),
		handlers:    make(map[string]ToolHandler),
		lastUpdated: time.Now(),
	}
}

// Register adds a tool to the registry
func (r *Registry) Register(tool *Tool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if tool.Name == "" {
		return ErrEmptyName
	}
	if tool.Enabled {
		if tool.Handler == nil {
			return ErrMissingHandler
		}
	}

	tool.CreatedAt = time.Now()
	tool.UpdatedAt = time.Now()

	r.tools[tool.Name] = tool

	// Add to category
	if tool.Category != "" {
		r.categories[tool.Category] = append(r.categories[tool.Category], tool.Name)
	}

	r.lastUpdated = time.Now()
	return nil
}

// Get retrieves a tool by name
func (r *Registry) Get(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tool, exists := r.tools[name]
	if !exists {
		return nil, false
	}
	return tool, true
}

// GetAll returns all registered tools
func (r *Registry) GetAll() []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]*Tool, 0, len(r.tools))
	for _, tool := range r.tools {
		tools = append(tools, tool)
	}
	return tools
}

// GetByCategory returns tools in a category
func (r *Registry) GetByCategory(category string) []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]*Tool, 0)
	if toolNames, ok := r.categories[category]; ok {
		for _, name := range toolNames {
			if tool, exists := r.tools[name]; exists {
				tools = append(tools, tool)
			}
		}
	}
	return tools
}

// Search discovers tools matching query
func (r *Registry) Search(query, category string) *DiscoveryResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	matches := make([]*Tool, 0)

	for _, tool := range r.tools {
		// Filter by category first
		if category != "" && tool.Category != category {
			continue
		}

		// Search by name, description
		if query != "" {
			if strings.Contains(strings.ToLower(tool.Name), strings.ToLower(query)) {
				matches = append(matches, tool)
				continue
			}
			if strings.Contains(strings.ToLower(tool.Description), strings.ToLower(query)) {
				matches = append(matches, tool)
				continue
			}
			// Search parameters
			for _, param := range tool.Parameters {
				if strings.Contains(strings.ToLower(param.Name), strings.ToLower(query)) ||
					strings.Contains(strings.ToLower(param.Description), strings.ToLower(query)) {
					matches = append(matches, tool)
					break
				}
			}
		} else {
			matches = append(matches, tool)
		}
	}

	return &DiscoveryResult{
		Tools:      matches,
		TotalCount: len(matches),
		Query:      query,
		Category:   category,
	}
}

// Unregister removes a tool
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tool, exists := r.tools[name]
	if !exists {
		return ErrToolNotFound
	}

	// Remove from category
	if tool.Category != "" {
		for i, t := range r.categories[tool.Category] {
			if t == name {
				r.categories[tool.Category] = append(r.categories[tool.Category][:i], r.categories[tool.Category][i+1:]...)
				break
			}
		}
	}

	delete(r.tools, name)
	r.lastUpdated = time.Now()
	return nil
}

// Enable enables a tool
func (r *Registry) Enable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tool, exists := r.tools[name]
	if !exists {
		return ErrToolNotFound
	}
	if tool.Handler == nil {
		return ErrMissingHandler
	}
	tool.Enabled = true
	tool.UpdatedAt = time.Now()
	r.lastUpdated = time.Now()
	return nil
}

// Disable disables a tool
func (r *Registry) Disable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tool, exists := r.tools[name]
	if !exists {
		return ErrToolNotFound
	}
	tool.Enabled = false
	tool.UpdatedAt = time.Now()
	r.lastUpdated = time.Now()
	return nil
}

// Update updates tool metadata
func (r *Registry) Update(name string, updates map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tool, exists := r.tools[name]
	if !exists {
		return ErrToolNotFound
	}

	for k, v := range updates {
		switch k {
		case "description":
			if s, ok := v.(string); ok {
				tool.Description = s
			}
		case "risk_level":
			if i, ok := v.(int); ok {
				tool.RiskLevel = i
			}
		case "rate_limit":
			if rl, ok := v.(*RateLimitConfig); ok {
				tool.RateLimit = rl
			}
		case "metadata":
			if m, ok := v.(map[string]interface{}); ok {
				tool.Metadata = m
			}
		}
	}

	tool.UpdatedAt = time.Now()
	r.lastUpdated = time.Now()
	return nil
}

// HasTool checks if a tool exists
func (r *Registry) HasTool(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.tools[name]
	return exists
}

// Count returns the number of registered tools
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

// ListCategories returns all categories with tool counts
func (r *Registry) ListCategories() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]int)
	for cat, tools := range r.categories {
		result[cat] = len(tools)
	}
	return result
}

// GetStats returns registry statistics
func (r *Registry) GetStats() *Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	enabled := 0
	totalRisk := 0
	for _, tool := range r.tools {
		if tool.Enabled {
			enabled++
		}
		totalRisk += tool.RiskLevel
	}

	return &Stats{
		TotalTools:       len(r.tools),
		EnabledTools:     enabled,
		DisabledTools:    len(r.tools) - enabled,
		AverageRiskLevel: 0,
		LastUpdated:      r.lastUpdated,
	}
}

// Stats holds registry statistics
type Stats struct {
	TotalTools       int       `json:"total_tools"`
	EnabledTools     int       `json:"enabled_tools"`
	DisabledTools    int       `json:"disabled_tools"`
	AverageRiskLevel int       `json:"average_risk_level"`
	LastUpdated      time.Time `json:"last_updated"`
}

// Errors
var (
	ErrEmptyName      = errors.New("tool name cannot be empty")
	ErrMissingHandler = errors.New("tool handler required for enabled tools")
	ErrToolNotFound   = errors.New("tool not found")
)