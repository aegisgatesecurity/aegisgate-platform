package toolregistry

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

type mockHandler struct {
	execFunc     func(context.Context, map[string]interface{}) (interface{}, error)
	validateFunc func(map[string]interface{}) error
}

func (m *mockHandler) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if m.execFunc != nil {
		return m.execFunc(ctx, params)
	}
	return nil, nil
}

func (m *mockHandler) Validate(params map[string]interface{}) error {
	if m.validateFunc != nil {
		return m.validateFunc(params)
	}
	return nil
}

func TestNewRegistry(t *testing.T) {
	reg := NewRegistry()
	if reg == nil {
		t.Fatal("NewRegistry() returned nil")
	}
	if reg.tools == nil {
		t.Error("tools map not initialized")
	}
	if reg.categories == nil {
		t.Error("categories map not initialized")
	}
}

func TestRegistryRegister(t *testing.T) {
	reg := NewRegistry()

	tool := &Tool{
		Name:        "file_read",
		Description: "Read files",
		Category:    "filesystem",
		Enabled:     true,
		Handler:     &mockHandler{},
	}

	err := reg.Register(tool)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	retrieved, ok := reg.Get("file_read")
	if !ok {
		t.Fatal("Get() tool not found")
	}
	if retrieved.Name != "file_read" {
		t.Errorf("Name = %s, want file_read", retrieved.Name)
	}
}

func TestRegistryRegisterEmptyName(t *testing.T) {
	reg := NewRegistry()

	tool := &Tool{Name: ""}
	err := reg.Register(tool)
	if err != ErrEmptyName {
		t.Errorf("Register() error = %v, want ErrEmptyName", err)
	}
}

func TestRegistryRegisterMissingHandler(t *testing.T) {
	reg := NewRegistry()

	tool := &Tool{
		Name:    "test",
		Enabled: true,
		Handler: nil,
	}
	err := reg.Register(tool)
	if err != ErrMissingHandler {
		t.Errorf("Register() error = %v, want ErrMissingHandler", err)
	}
}

func TestRegistryGetAll(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "tool1", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool2", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool3", Handler: &mockHandler{}})

	all := reg.GetAll()
	if len(all) != 3 {
		t.Errorf("GetAll() count = %d, want 3", len(all))
	}
}

func TestRegistryGetByCategory(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "file_read", Category: "filesystem", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "file_write", Category: "filesystem", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "network", Category: "network", Handler: &mockHandler{}})

	fsTools := reg.GetByCategory("filesystem")
	if len(fsTools) != 2 {
		t.Errorf("GetByCategory(filesystem) = %d, want 2", len(fsTools))
	}

	netTools := reg.GetByCategory("network")
	if len(netTools) != 1 {
		t.Errorf("GetByCategory(network) = %d, want 1", len(netTools))
	}
}

func TestRegistrySearchByName(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "file_read", Description: "Read a file", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "file_write", Description: "Write to a file", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "http_get", Description: "HTTP GET request", Handler: &mockHandler{}})

	result := reg.Search("file", "")
	if result.TotalCount != 2 {
		t.Errorf("Search('file') count = %d, want 2", result.TotalCount)
	}
}

func TestRegistrySearchByDescription(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "tool1", Description: "Read data from files", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool2", Description: "Write data to files", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool3", Description: "Send HTTP requests", Handler: &mockHandler{}})

	result := reg.Search("data", "")
	if result.TotalCount != 2 {
		t.Errorf("Search('data') count = %d, want 2", result.TotalCount)
	}
}

func TestRegistrySearchByCategory(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "file_read", Category: "fs", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "file_write", Category: "fs", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "network", Category: "net", Handler: &mockHandler{}})

	result := reg.Search("", "fs")
	if result.TotalCount != 2 {
		t.Errorf("Search('', 'fs') count = %d, want 2", result.TotalCount)
	}
}

func TestRegistryUnregister(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "tool", Category: "cat", Handler: &mockHandler{}})

	err := reg.Unregister("tool")
	if err != nil {
		t.Fatalf("Unregister() error = %v", err)
	}

	_, ok := reg.Get("tool")
	if ok {
		t.Error("Get() after Unregister() should return false")
	}
}

func TestRegistryUnregisterNotFound(t *testing.T) {
	reg := NewRegistry()

	err := reg.Unregister("nonexistent")
	if err != ErrToolNotFound {
		t.Errorf("Unregister() error = %v, want ErrToolNotFound", err)
	}
}

func TestRegistryEnable(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "tool", Handler: &mockHandler{}})

	err := reg.Enable("tool")
	if err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	tool, _ := reg.Get("tool")
	if !tool.Enabled {
		t.Error("Tool should be enabled")
	}
}

func TestRegistryDisable(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "tool", Enabled: true, Handler: &mockHandler{}})

	err := reg.Disable("tool")
	if err != nil {
		t.Fatalf("Disable() error = %v", err)
	}

	tool, _ := reg.Get("tool")
	if tool.Enabled {
		t.Error("Tool should be disabled")
	}
}

func TestRegistryEnableNotFound(t *testing.T) {
	reg := NewRegistry()

	err := reg.Enable("nonexistent")
	if err != ErrToolNotFound {
		t.Errorf("Enable() error = %v, want ErrToolNotFound", err)
	}
}

func TestRegistryDisableNotFound(t *testing.T) {
	reg := NewRegistry()

	err := reg.Disable("nonexistent")
	if err != ErrToolNotFound {
		t.Errorf("Disable() error = %v, want ErrToolNotFound", err)
	}
}

func TestRegistryUpdate(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{
		Name:        "tool",
		Description: "old desc",
		RiskLevel:   30,
		Handler:     &mockHandler{},
	})

	updates := map[string]interface{}{
		"description": "new desc",
		"risk_level":  75,
	}
	err := reg.Update("tool", updates)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	tool, _ := reg.Get("tool")
	if tool.Description != "new desc" {
		t.Errorf("Description = %s, want 'new desc'", tool.Description)
	}
	if tool.RiskLevel != 75 {
		t.Errorf("RiskLevel = %d, want 75", tool.RiskLevel)
	}
}

func TestRegistryHasTool(t *testing.T) {
	reg := NewRegistry()

	if reg.HasTool("tool") {
		t.Error("HasTool() should return false")
	}

	reg.Register(&Tool{Name: "tool", Handler: &mockHandler{}})

	if !reg.HasTool("tool") {
		t.Error("HasTool() should return true")
	}
}

func TestRegistryCount(t *testing.T) {
	reg := NewRegistry()

	if reg.Count() != 0 {
		t.Error("Count() should be 0")
	}

	reg.Register(&Tool{Name: "tool1", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool2", Handler: &mockHandler{}})

	if reg.Count() != 2 {
		t.Errorf("Count() = %d, want 2", reg.Count())
	}
}

func TestRegistryListCategories(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "tool1", Category: "cat1", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool2", Category: "cat1", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool3", Category: "cat2", Handler: &mockHandler{}})

	cats := reg.ListCategories()
	if len(cats) != 2 {
		t.Errorf("ListCategories() = %d categories, want 2", len(cats))
	}
	if cats["cat1"] != 2 {
		t.Errorf("cat1 count = %d, want 2", cats["cat1"])
	}
	if cats["cat2"] != 1 {
		t.Errorf("cat2 count = %d, want 1", cats["cat2"])
	}
}

func TestRegistryGetStats(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "tool1", Enabled: true, RiskLevel: 50, Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool2", Enabled: false, RiskLevel: 30, Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool3", Enabled: true, RiskLevel: 70, Handler: &mockHandler{}})

	stats := reg.GetStats()
	if stats.TotalTools != 3 {
		t.Errorf("TotalTools = %d, want 3", stats.TotalTools)
	}
	if stats.EnabledTools != 2 {
		t.Errorf("EnabledTools = %d, want 2", stats.EnabledTools)
	}
	if stats.DisabledTools != 1 {
		t.Errorf("DisabledTools = %d, want 1", stats.DisabledTools)
	}
	t.Logf("Stats: %+v", stats)
}

func TestRegistryToolTimestamps(t *testing.T) {
	reg := NewRegistry()

	tool := &Tool{Name: "tool", Handler: &mockHandler{}}
	reg.Register(tool)

	if tool.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if tool.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestRegistryEmptySearch(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "tool1", Handler: &mockHandler{}})
	reg.Register(&Tool{Name: "tool2", Handler: &mockHandler{}})

	result := reg.Search("", "")
	if result.TotalCount != 2 {
		t.Errorf("Empty search count = %d, want 2", result.TotalCount)
	}
}

func TestRegistrySearchNoMatches(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&Tool{Name: "file_read", Handler: &mockHandler{}})

	result := reg.Search("nonexistent", "")
	if result.TotalCount != 0 {
		t.Errorf("No matches count = %d, want 0", result.TotalCount)
	}
}

func TestRegistryConcurrent(t *testing.T) {
	reg := NewRegistry()
	var wg sync.WaitGroup
	errors := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			err := reg.Register(&Tool{Name: fmt.Sprintf("tool_%d", n), Handler: &mockHandler{}})
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent register error: %v", err)
	}

	if reg.Count() != 50 {
		t.Errorf("Expected 50 tools, got %d", reg.Count())
	}
}
