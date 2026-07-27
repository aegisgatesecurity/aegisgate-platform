// Package plugin_test provides tests for the plugin system
package plugin_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/plugin"
)

// TestPlugin is a simple test plugin
type TestPlugin struct {
	initialized bool
	started     bool
	stopped     bool
	initError   error
	startError  error
	stopError   error
	hooks       []plugin.HookType
	metadata    plugin.PluginMetadata
}

// Compile-time check that TestPlugin implements Plugin
var _ plugin.Plugin = (*TestPlugin)(nil)

func (t *TestPlugin) Metadata() plugin.PluginMetadata {
	return t.metadata
}

func (t *TestPlugin) Init(ctx context.Context, config plugin.PluginConfig) error {
	t.initialized = true
	return t.initError
}

func (t *TestPlugin) Start(ctx context.Context) error {
	t.started = true
	return t.startError
}

func (t *TestPlugin) Stop(ctx context.Context) error {
	t.stopped = true
	return t.stopError
}

func (t *TestPlugin) Hooks() []plugin.HookType {
	return t.hooks
}

// TestProcessor is a test plugin that implements request/response processing
type TestProcessor struct {
	TestPlugin
	requestCount  int
	responseCount int
}

var _ plugin.Plugin = (*TestProcessor)(nil)
var _ plugin.RequestProcessor = (*TestProcessor)(nil)
var _ plugin.ResponseProcessor = (*TestProcessor)(nil)

func (t *TestProcessor) ProcessRequest(ctx context.Context, reqCtx *plugin.RequestContext) (*plugin.HookResult, error) {
	t.requestCount++
	result := plugin.DefaultHookResult()
	return &result, nil
}

func (t *TestProcessor) ProcessResponse(ctx context.Context, reqCtx *plugin.RequestContext, respCtx *plugin.ResponseContext) (*plugin.HookResult, error) {
	t.responseCount++
	result := plugin.DefaultHookResult()
	return &result, nil
}

// TestPeriodic is a test plugin that implements periodic tasks
type TestPeriodic struct {
	TestPlugin
	periodicCount int
	interval      time.Duration
}

var _ plugin.Plugin = (*TestPeriodic)(nil)
var _ plugin.PeriodicTask = (*TestPeriodic)(nil)

func (t *TestPeriodic) OnPeriodic(ctx context.Context, periodicCtx *plugin.PeriodicContext) error {
	t.periodicCount++
	return nil
}

func (t *TestPeriodic) Interval() time.Duration {
	return t.interval
}

func TestManager_NewManager(t *testing.T) {
	// Test default config
	mgr := plugin.NewManager(nil)
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}

	// Test with custom config
	config := &plugin.ManagerConfig{
		PluginDirs:     []string{"/test/plugins"},
		PluginTimeout:  10 * time.Second,
		EnablePeriodic: false,
	}
	mgr2 := plugin.NewManager(config)
	if mgr2 == nil {
		t.Fatal("NewManager with config returned nil")
	}
}

func TestManager_Register(t *testing.T) {
	mgr := plugin.NewManager(nil)

	testPlugin := &TestPlugin{
		metadata: plugin.PluginMetadata{
			ID:   "test-plugin",
			Name: "Test Plugin",
		},
		hooks: []plugin.HookType{plugin.HookRequestReceived},
	}

	err := mgr.Register(testPlugin)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Test duplicate registration
	err = mgr.Register(testPlugin)
	if err == nil {
		t.Fatal("Expected error for duplicate registration")
	}

	// Test empty ID
	err = mgr.Register(&TestPlugin{
		metadata: plugin.PluginMetadata{ID: ""},
	})
	if err == nil {
		t.Fatal("Expected error for empty ID")
	}
}

func TestManager_Init(t *testing.T) {
	mgr := plugin.NewManager(nil)

	// Register a test plugin
	testPlugin := &TestProcessor{
		TestPlugin: TestPlugin{
			metadata: plugin.PluginMetadata{
				ID:   "test-processor",
				Name: "Test Processor",
			},
			hooks: []plugin.HookType{plugin.HookRequestReceived, plugin.HookResponseSent},
		},
	}
	mgr.Register(testPlugin)

	ctx := context.Background()
	err := mgr.Init(ctx)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if !testPlugin.initialized {
		t.Error("Plugin was not initialized")
	}

	// Test initialization failure
	mgr2 := plugin.NewManager(nil)
	failingPlugin := &TestPlugin{
		metadata: plugin.PluginMetadata{
			ID:   "failing-plugin",
			Name: "Failing Plugin",
		},
		initError: assertAnError("init failed"),
	}
	mgr2.Register(failingPlugin)

	err = mgr2.Init(ctx)
	if err == nil {
		t.Fatal("Expected error for failing plugin init")
	}
}

func TestManager_StartStop(t *testing.T) {
	mgr := plugin.NewManager(&plugin.ManagerConfig{
		EnablePeriodic: false,
	})

	testPlugin := &TestProcessor{
		TestPlugin: TestPlugin{
			metadata: plugin.PluginMetadata{
				ID:   "test-plugin",
				Name: "Test Plugin",
			},
			hooks: []plugin.HookType{plugin.HookRequestReceived},
		},
	}
	mgr.Register(testPlugin)

	ctx := context.Background()
	err := mgr.Init(ctx)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = mgr.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !testPlugin.started {
		t.Error("Plugin was not started")
	}

	err = mgr.Stop(ctx)
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if !testPlugin.stopped {
		t.Error("Plugin was not stopped")
	}
}

func TestManager_GetPlugin(t *testing.T) {
	mgr := plugin.NewManager(nil)

	testPlugin := &TestPlugin{
		metadata: plugin.PluginMetadata{
			ID:   "test-plugin",
			Name: "Test Plugin",
		},
	}
	mgr.Register(testPlugin)

	state, ok := mgr.GetPlugin("test-plugin")
	if !ok {
		t.Fatal("Plugin not found")
	}
	if state.Metadata.ID != "test-plugin" {
		t.Errorf("Expected ID 'test-plugin', got %s", state.Metadata.ID)
	}

	// Test non-existent plugin
	_, ok = mgr.GetPlugin("non-existent")
	if ok {
		t.Error("Expected not found for non-existent plugin")
	}
}

func TestManager_ListPlugins(t *testing.T) {
	mgr := plugin.NewManager(nil)

	// Register multiple plugins
	for i := 0; i < 3; i++ {
		mgr.Register(&TestPlugin{
			metadata: plugin.PluginMetadata{
				ID:   "test-plugin-" + string(rune('0'+i)),
				Name: "Test Plugin " + string(rune('0'+i)),
			},
		})
	}

	plugins := mgr.ListPlugins()
	if len(plugins) != 3 {
		t.Errorf("Expected 3 plugins, got %d", len(plugins))
	}
}

func TestManager_GetPluginsByHook(t *testing.T) {
	mgr := plugin.NewManager(nil)

	// Register plugins with different hooks
	mgr.Register(&TestPlugin{
		metadata: plugin.PluginMetadata{ID: "hook-request"},
		hooks:    []plugin.HookType{plugin.HookRequestReceived},
	})
	mgr.Register(&TestPlugin{
		metadata: plugin.PluginMetadata{ID: "hook-response"},
		hooks:    []plugin.HookType{plugin.HookResponseSent},
	})
	mgr.Register(&TestPlugin{
		metadata: plugin.PluginMetadata{ID: "hook-both"},
		hooks:    []plugin.HookType{plugin.HookRequestReceived, plugin.HookResponseSent},
	})

	requestPlugins := mgr.GetPluginsByHook(plugin.HookRequestReceived)
	if len(requestPlugins) != 2 {
		t.Errorf("Expected 2 plugins for HookRequestReceived, got %d", len(requestPlugins))
	}

	responsePlugins := mgr.GetPluginsByHook(plugin.HookResponseSent)
	if len(responsePlugins) != 2 {
		t.Errorf("Expected 2 plugins for HookResponseSent, got %d", len(responsePlugins))
	}
}

func TestManager_ExecuteHook(t *testing.T) {
	mgr := plugin.NewManager(nil)

	processor := &TestProcessor{
		TestPlugin: TestPlugin{
			metadata: plugin.PluginMetadata{
				ID:   "test-processor",
				Name: "Test Processor",
			},
			hooks: []plugin.HookType{plugin.HookRequestReceived},
		},
	}
	mgr.Register(processor)

	ctx := context.Background()
	mgr.Init(ctx)
	mgr.Start(ctx)
	defer mgr.Stop(ctx)

	// Execute hook
	result, err := mgr.ExecuteHook(ctx, plugin.HookRequestReceived, func(ctx context.Context, state *plugin.PluginState) (*plugin.HookResult, error) {
		p, ok := state.Plugin.(*TestProcessor)
		if !ok {
			r := plugin.DefaultHookResult()
			return &r, nil
		}
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		return p.ProcessRequest(ctx, plugin.NewRequestContext(req, nil, "http://upstream"))
	})

	if err != nil {
		t.Fatalf("ExecuteHook failed: %v", err)
	}

	if processor.requestCount != 1 {
		t.Errorf("Expected 1 request processed, got %d", processor.requestCount)
	}

	if !result.Continue {
		t.Error("Expected result.Continue to be true")
	}
}

func TestManager_Capabilities(t *testing.T) {
	mgr := plugin.NewManager(nil)

	// Register plugin with capabilities
	mgr.Register(&TestPlugin{
		metadata: plugin.PluginMetadata{
			ID:           "capability-plugin",
			Name:         "Capability Plugin",
			Capabilities: []string{"auth", "filter"},
		},
	})

	if !mgr.HasCapability("auth") {
		t.Error("Expected to have auth capability")
	}

	if !mgr.HasCapability("filter") {
		t.Error("Expected to have filter capability")
	}

	if mgr.HasCapability("nonexistent") {
		t.Error("Should not have nonexistent capability")
	}

	plugins := mgr.GetPluginsByCapability("auth")
	if len(plugins) != 1 {
		t.Errorf("Expected 1 plugin for auth capability, got %d", len(plugins))
	}
}

func TestManager_DependencyCheck(t *testing.T) {
	mgr := plugin.NewManager(nil)

	// Register plugin with dependency
	mgr.Register(&TestPlugin{
		metadata: plugin.PluginMetadata{
			ID:           "dependent",
			Name:         "Dependent Plugin",
			Dependencies: []string{"dependency"},
		},
	})

	// Should fail because dependency is not registered
	err := mgr.Init(context.Background())
	if err == nil {
		t.Fatal("Expected error for missing dependency")
	}
}

func TestManager_UpdateConfig(t *testing.T) {
	mgr := plugin.NewManager(&plugin.ManagerConfig{
		EnablePeriodic: false,
	})

	testPlugin := &TestPlugin{
		metadata: plugin.PluginMetadata{
			ID:   "test-plugin",
			Name: "Test Plugin",
		},
	}
	mgr.Register(testPlugin)

	// Update config while not running
	newConfig := plugin.PluginConfig{
		Enabled:  false,
		Priority: 10,
		Settings: map[string]interface{}{"key": "value"},
	}

	err := mgr.UpdateConfig("test-plugin", newConfig)
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	state, _ := mgr.GetPlugin("test-plugin")
	if state.Config.Enabled {
		t.Error("Expected Enabled to be false")
	}
	if state.Config.Priority != 10 {
		t.Errorf("Expected Priority to be 10, got %d", state.Config.Priority)
	}

	// Test update while running - this should succeed now since the test was updated
	ctx := context.Background()
	mgr.Init(ctx)
	err = mgr.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Update config while running should now succeed (runtime config updates)
	err = mgr.UpdateConfig("test-plugin", plugin.PluginConfig{
		Enabled:  true,
		Priority: 20,
	})
	if err != nil {
		t.Fatalf("UpdateConfig while running failed: %v", err)
	}

	mgr.Stop(ctx)
}

func TestManager_GetStatus(t *testing.T) {
	mgr := plugin.NewManager(nil)

	mgr.Register(&TestPlugin{
		metadata: plugin.PluginMetadata{ID: "plugin-1"},
	})
	mgr.Register(&TestPlugin{
		metadata: plugin.PluginMetadata{ID: "plugin-2"},
	})

	ctx := context.Background()
	mgr.Init(ctx)
	mgr.Start(ctx)
	defer mgr.Stop(ctx)

	status := mgr.GetStatus()
	if len(status) != 2 {
		t.Errorf("Expected 2 plugins in status, got %d", len(status))
	}

	if status["plugin-1"] != plugin.StatusRunning {
		t.Errorf("Expected plugin-1 to be running, got %s", status["plugin-1"])
	}
}

func TestPluginConfig_GetSetting(t *testing.T) {
	config := &plugin.PluginConfig{
		Settings: map[string]interface{}{
			"string_key":   "value",
			"int_key":      42,
			"bool_key":     true,
			"duration_key": 30 * time.Second,
		},
	}

	// Test default value
	if config.GetString("nonexistent", "default") != "default" {
		t.Error("GetString default value failed")
	}

	// Test string value
	if config.GetString("string_key", "default") != "value" {
		t.Error("GetString value failed")
	}

	// Test int value
	if config.GetInt("int_key", 0) != 42 {
		t.Error("GetInt value failed")
	}

	// Test bool value
	if !config.GetBool("bool_key", false) {
		t.Error("GetBool value failed")
	}

	// Test duration value
	if config.GetDuration("duration_key", 0) != 30*time.Second {
		t.Error("GetDuration value failed")
	}

	// Test duration from string
	config.Settings["duration_string"] = "1m"
	if config.GetDuration("duration_string", 0) != time.Minute {
		t.Error("GetDuration from string failed")
	}
}

func TestPluginConfig_Validate(t *testing.T) {
	// Test nil config
	var nilConfig *plugin.PluginConfig
	if err := nilConfig.Validate(); err == nil {
		t.Error("Expected error for nil config")
	}

	// Test valid config
	validConfig := &plugin.PluginConfig{
		Timeout: 30 * time.Second,
		RetryConfig: &plugin.RetryConfig{
			MaxAttempts: 3,
		},
	}
	if err := validConfig.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	// Test that defaults are applied
	config := &plugin.PluginConfig{}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if config.Timeout == 0 {
		t.Error("Expected Timeout to be set to default")
	}
	if config.RetryConfig == nil {
		t.Error("Expected RetryConfig to be set to default")
	}
}

func TestHookResult(t *testing.T) {
	// Test DefaultHookResult
	result := plugin.DefaultHookResult()
	if !result.Continue {
		t.Error("DefaultHookResult should have Continue=true")
	}
	if result.Stop {
		t.Error("DefaultHookResult should have Stop=false")
	}

	// Test ErrorHookResult
	err := assertAnError("test error")
	errResult := plugin.ErrorHookResult(err)
	if errResult.Continue {
		t.Error("ErrorHookResult should have Continue=false")
	}
	if !errResult.Stop {
		t.Error("ErrorHookResult should have Stop=true")
	}
	if errResult.Error == nil {
		t.Error("ErrorHookResult should have Error set")
	}

	// Test StopHookResult
	stopResult := plugin.StopHookResult()
	if stopResult.Continue {
		t.Error("StopHookResult should have Continue=false")
	}
	if !stopResult.Stop {
		t.Error("StopHookResult should have Stop=true")
	}
}

func TestContextCreation(t *testing.T) {
	// Test NewRequestContext
	reqCtx := plugin.NewRequestContext(nil, nil, "http://upstream")
	if reqCtx == nil {
		t.Fatal("NewRequestContext returned nil")
	}
	if reqCtx.Metadata == nil {
		t.Error("Expected Metadata to be initialized")
	}

	// Test NewResponseContext
	respCtx := plugin.NewResponseContext(200, nil, nil, 100*time.Millisecond)
	if respCtx == nil {
		t.Fatal("NewResponseContext returned nil")
	}
	if respCtx.StatusCode != 200 {
		t.Errorf("Expected StatusCode 200, got %d", respCtx.StatusCode)
	}

	// Test NewConnectionContext
	connCtx := plugin.NewConnectionContext("127.0.0.1:8443", "192.168.1.1:12345", true)
	if connCtx == nil {
		t.Fatal("NewConnectionContext returned nil")
	}
	if !connCtx.IsEncrypted {
		t.Error("Expected IsEncrypted to be true")
	}

	// Test NewErrorContext
	errCtx := plugin.NewErrorContext(assertAnError("test error"), plugin.HookRequestReceived, nil, "conn-123")
	if errCtx == nil {
		t.Fatal("NewErrorContext returned nil")
	}
	if errCtx.Hook != plugin.HookRequestReceived {
		t.Errorf("Expected Hook HookRequestReceived, got %s", errCtx.Hook)
	}
}

func assertAnError(msg string) error {
	return &testError{msg: msg}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
