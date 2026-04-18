package server

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	agentcomm "github.com/aegisguardsecurity/aegisguard/pkg/agent-comm"
	mcpserver "github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
	ratelimit "github.com/aegisguardsecurity/aegisguard/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestConfig() *ServerConfig {
	return &ServerConfig{
		Server: ServerBasicConfig{
			Name:         "test-server",
			Host:         "localhost",
			Port:         8080,
			MaxChannels:  10,
			MessageQueue: 100,
		},
		Policy: policyConfig{
			MaxPriority: 10,
		},
		RateLimit: ratelimit.Config{
			RequestsPerSecond: 100,
			BurstSize:         50,
		},
		Channels: []ChannelConfig{
			{
				Name:           "default",
				AgentIDs:       []string{"agent-1", "agent-2"},
				MaxMessages:    100,
				PriorityEnable: true,
			},
		},
		Audit: auditConfig{
			LogFile:    "test-audit.log",
			MaxEntries: 1000,
			Retention:  "24h",
		},
		ContextIsolator: isolatorConfig{
			Enabled: true,
		},
		ToolRegistry: toolregistryConfig{
			MaxTools: 50,
		},
		MCP: mcpserver.ServerConfig{
			Address: "localhost:8081",
		},
	}
}

func TestServerNewServer(t *testing.T) {
	config := createTestConfig()

	s, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.NotNil(t, s.toolRegistry)
	assert.NotNil(t, s.policyEngine)
	assert.NotNil(t, s.auditLogger)
	assert.NotNil(t, s.rateLimiter)
	assert.NotNil(t, s.contextIsolator)
	assert.NotNil(t, s.mcpServer)
	assert.Len(t, s.commChannels, 1)
	assert.Contains(t, s.commChannels, "default")
	assert.False(t, s.IsRunning())
	assert.Zero(t, s.Uptime())

	if s.cancel != nil {
		s.cancel()
	}
}

func TestServerNilConfig(t *testing.T) {
	s, err := NewServer(nil)
	assert.Error(t, err)
	assert.Nil(t, s)
	assert.EqualError(t, err, "config cannot be nil")
}

func TestServerGetters(t *testing.T) {
	config := createTestConfig()
	s, err := NewServer(config)
	require.NoError(t, err)
	defer func() {
		if s.cancel != nil {
			s.cancel()
		}
	}()

	// Test GetToolRegistry
	tr := s.GetToolRegistry()
	assert.NotNil(t, tr)
	assert.Equal(t, s.toolRegistry, tr)

	// Test GetPolicyEngine
	pe := s.GetPolicyEngine()
	assert.NotNil(t, pe)
	assert.Equal(t, s.policyEngine, pe)

	// Test GetCommChannel
	ch, ok := s.GetCommChannel("default")
	assert.True(t, ok)
	assert.NotNil(t, ch)

	// Test non-existent channel
	_, ok = s.GetCommChannel("non-existent")
	assert.False(t, ok)

	// Test ListCommChannels
	names := s.ListCommChannels()
	assert.Len(t, names, 1)
	assert.Contains(t, names, "default")
}

func TestServerStartStop(t *testing.T) {
	config := createTestConfig()
	s, err := NewServer(config)
	require.NoError(t, err)
	defer os.Remove("test-audit.log")

	// Test Start
	err = s.Start()
	require.NoError(t, err)
	assert.True(t, s.IsRunning())
	assert.NotZero(t, s.Uptime())

	// Test double Start
	err = s.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Let server run briefly
	time.Sleep(150 * time.Millisecond)

	// Test Stop
	err = s.Stop()
	require.NoError(t, err)
	assert.False(t, s.IsRunning())

	// Test double Stop
	err = s.Stop()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")
}

func TestServerRun(t *testing.T) {
	config := createTestConfig()
	s, err := NewServer(config)
	require.NoError(t, err)
	defer os.Remove("test-audit.log")

	// Run in goroutine
	done := make(chan struct{})
	var runErr error
	go func() {
		runErr = s.Run()
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	assert.True(t, s.IsRunning())

	// The Run() method will stop itself when ctx is cancelled
	// We need to cancel the context directly instead of calling Stop()
	s.cancel()

	// Wait for Run to return
	select {
	case <-done:
		// Success - Run completed
		assert.NoError(t, runErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestServerLoadConfig(t *testing.T) {
	config := createTestConfig()

	// Write config to file
	data, err := json.Marshal(config)
	require.NoError(t, err)

	err = os.WriteFile("test-config.json", data, 0644)
	require.NoError(t, err)
	defer os.Remove("test-config.json")

	// Load config
	loaded, err := LoadConfig("test-config.json")
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "test-server", loaded.Server.Name)
	assert.Equal(t, 8080, loaded.Server.Port)
	assert.Len(t, loaded.Channels, 1)
	assert.Equal(t, "default", loaded.Channels[0].Name)

	// Test non-existent file
	_, err = LoadConfig("non-existent.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")

	// Test invalid JSON
	err = os.WriteFile("invalid.json", []byte("{invalid json}"), 0644)
	require.NoError(t, err)
	defer os.Remove("invalid.json")

	_, err = LoadConfig("invalid.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestServerWithMultipleChannels(t *testing.T) {
	config := &ServerConfig{
		Server: ServerBasicConfig{
			Name:         "multi-channel",
			Host:         "localhost",
			Port:         8082,
			MaxChannels:  10,
			MessageQueue: 100,
		},
		Policy:    policyConfig{MaxPriority: 10},
		RateLimit: ratelimit.Config{RequestsPerSecond: 60, BurstSize: 30},
		Channels: []ChannelConfig{
			{Name: "channel-1", AgentIDs: []string{"agent-1"}, MaxMessages: 50},
			{Name: "channel-2", AgentIDs: []string{"agent-2"}, MaxMessages: 50},
			{Name: "channel-3", AgentIDs: []string{"agent-3"}, MaxMessages: 50},
		},
		Audit:           auditConfig{LogFile: "test-audit.log"},
		ContextIsolator: isolatorConfig{Enabled: true},
		ToolRegistry:    toolregistryConfig{MaxTools: 100},
		MCP:             mcpserver.ServerConfig{Address: "localhost:8083"},
	}

	s, err := NewServer(config)
	require.NoError(t, err)
	defer func() {
		if s.cancel != nil {
			s.cancel()
		}
		os.Remove("test-audit.log")
	}()

	assert.Len(t, s.commChannels, 3)
	assert.Contains(t, s.commChannels, "channel-1")
	assert.Contains(t, s.commChannels, "channel-2")
	assert.Contains(t, s.commChannels, "channel-3")

	names := s.ListCommChannels()
	assert.Len(t, names, 3)
}

func TestServerProcessMessageTypes(t *testing.T) {
	config := createTestConfig()
	s, err := NewServer(config)
	require.NoError(t, err)
	defer func() {
		if s.cancel != nil {
			s.cancel()
		}
		os.Remove("test-audit.log")
	}()

	// Test request handling
	reqMsg := &agentcomm.Message{
		ID:       "req-1",
		Type:     agentcomm.MessageTypeRequest,
		Sender:   "agent-1",
		Payload:  "request data",
		Priority: 5,
	}
	s.processMessage(reqMsg)

	// Test command handling
	cmdMsg := &agentcomm.Message{
		ID:       "cmd-1",
		Type:     agentcomm.MessageTypeCommand,
		Sender:   "agent-1",
		Payload:  "command data",
		Priority: 5,
	}
	s.processMessage(cmdMsg)

	// Test event handling
	eventMsg := &agentcomm.Message{
		ID:       "evt-1",
		Type:     agentcomm.MessageTypeEvent,
		Sender:   "agent-1",
		Payload:  "event data",
		Priority: 5,
	}
	s.processMessage(eventMsg)

	// Test heartbeat
	hbMsg := &agentcomm.Message{
		ID:       "hb-1",
		Type:     agentcomm.MessageTypeHeartbeat,
		Sender:   "agent-1",
		Priority: 1,
	}
	s.processMessage(hbMsg)

	// Test error
	errMsg := &agentcomm.Message{
		ID:       "err-1",
		Type:     agentcomm.MessageTypeError,
		Sender:   "agent-1",
		Payload:  "error occurred",
		Priority: 10,
	}
	s.processMessage(errMsg)

	// Test unknown type
	unknownMsg := &agentcomm.Message{
		ID:       "unk-1",
		Type:     "unknown",
		Sender:   "agent-1",
		Priority: 1,
	}
	s.processMessage(unknownMsg)

	entries := s.auditLogger.GetEntries()
	assert.Greater(t, len(entries), 5)
}

func TestServerUptimeAccuracy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping uptime test in short mode")
	}
	config := createTestConfig()
	s, err := NewServer(config)
	require.NoError(t, err)
	defer os.Remove("test-audit.log")

	err = s.Start()
	require.NoError(t, err)

	// Give the server time to run
	time.Sleep(100 * time.Millisecond)

	uptime := s.Uptime()
	assert.NotZero(t, uptime)
	// Just verify uptime is greater than the time we slept
	assert.GreaterOrEqual(t, uptime.Milliseconds(), int64(50))

	err = s.Stop()
	require.NoError(t, err)
}

func TestServerChannelPublishReceive(t *testing.T) {
	config := createTestConfig()
	s, err := NewServer(config)
	require.NoError(t, err)
	defer func() {
		if s.cancel != nil {
			s.cancel()
		}
		os.Remove("test-audit.log")
	}()

	ch, ok := s.GetCommChannel("default")
	require.True(t, ok)

	// Publish test message
	msg := agentcomm.NewMessage(agentcomm.MessageTypeRequest, "agent-1", "server", "test")
	err = ch.Send(msg)
	require.NoError(t, err)

	messages := ch.Peek()
	assert.Len(t, messages, 1)

	count := ch.MessageCount()
	assert.Equal(t, 1, count)

	// Clear the channel
	ch.Clear()
	messages = ch.Peek()
	assert.Empty(t, messages)
}

func TestServerConfigRoundTrip(t *testing.T) {
	config := createTestConfig()

	// Marshal to JSON
	data, err := json.Marshal(config)
	require.NoError(t, err)

	// Unmarshal back
	var loaded ServerConfig
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)

	assert.Equal(t, config.Server.Name, loaded.Server.Name)
	assert.Equal(t, config.Server.Port, loaded.Server.Port)
	assert.Equal(t, len(config.Channels), len(loaded.Channels))
}
