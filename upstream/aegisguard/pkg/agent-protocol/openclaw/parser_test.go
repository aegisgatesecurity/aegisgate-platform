package openclaw

import (
	"encoding/json"
	"testing"
)

func TestNewParser(t *testing.T) {
	p := NewParser()
	if p == nil {
		t.Fatal("NewParser() returned nil")
	}
}

func TestParseMessage_Valid(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name: "basic tool call",
			json: `{
				"type": "tool",
				"action": "tool.call",
				"payload": {"name": "file_read", "args": {"path": "/tmp/test.txt"}}
			}`,
			wantErr: false,
		},
		{
			name: "with meta",
			json: `{
				"type": "tool",
				"action": "tool.call",
				"payload": {"name": "shell_command", "args": {"cmd": "ls"}},
				"meta": {"session_id": "sess-123", "agent_id": "openclaw-1"}
			}`,
			wantErr: false,
		},
		{
			name: "alternate action format",
			json: `{
				"type": "action",
				"action": "execute",
				"payload": {"tool": "web_search", "arguments": {"query": "golang"}}
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := p.ParseMessage([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && msg == nil {
				t.Error("ParseMessage() returned nil message")
			}
		})
	}
}

func TestParseMessage_Invalid(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name:    "empty data",
			json:    "",
			wantErr: true,
		},
		{
			name:    "invalid json",
			json:    `{invalid}`,
			wantErr: true,
		},
		{
			name:    "missing type",
			json:    `{"action": "tool.call", "payload": {}}`,
			wantErr: true,
		},
		{
			name:    "missing action",
			json:    `{"type": "tool", "payload": {}}`,
			wantErr: true,
		},
		{
			name:    "missing payload",
			json:    `{"type": "tool", "action": "tool.call"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ParseMessage([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseToolCall_Valid(t *testing.T) {
	p := NewParser()

	msg := &OpenClawMessage{
		Type:   "tool",
		Action: "tool.call",
		Payload: map[string]interface{}{
			"name": "file_read",
			"args": map[string]interface{}{
				"path": "/tmp/test.txt",
			},
		},
		Meta: map[string]interface{}{
			"session_id": "sess-abc",
		},
	}

	tc, err := p.ParseToolCall(msg)
	if err != nil {
		t.Fatalf("ParseToolCall() error = %v", err)
	}

	if tc.Name != "file_read" {
		t.Errorf("Name = %s, want file_read", tc.Name)
	}
	if tc.SessionID != "sess-abc" {
		t.Errorf("SessionID = %s, want sess-abc", tc.SessionID)
	}
	if tc.ActionType != "tool.call" {
		t.Errorf("ActionType = %s, want tool.call", tc.ActionType)
	}
}

func TestParseToolCall_ValidAlternateFields(t *testing.T) {
	p := NewParser()

	msg := &OpenClawMessage{
		Type:   "action",
		Action: "execute",
		Payload: map[string]interface{}{
			"tool":   "web_search",
			"params": map[string]interface{}{"query": "test"},
		},
		Meta: map[string]interface{}{
			"sessionId": "sess-xyz",
			"contextId": "ctx-001",
		},
	}

	tc, err := p.ParseToolCall(msg)
	if err != nil {
		t.Fatalf("ParseToolCall() error = %v", err)
	}

	if tc.Name != "web_search" {
		t.Errorf("Name = %s, want web_search", tc.Name)
	}
	if tc.SessionID != "sess-xyz" {
		t.Errorf("SessionID = %s, want sess-xyz", tc.SessionID)
	}
	if tc.ContextID != "ctx-001" {
		t.Errorf("ContextID = %s, want ctx-001", tc.ContextID)
	}
}

func TestParseToolCall_Invalid(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name    string
		msg     *OpenClawMessage
		wantErr bool
	}{
		{
			name:    "nil message",
			msg:     nil,
			wantErr: true,
		},
		{
			name: "invalid type",
			msg: &OpenClawMessage{
				Type:    "unknown",
				Action:  "tool.call",
				Payload: map[string]interface{}{"name": "test"},
			},
			wantErr: true,
		},
		{
			name: "invalid action",
			msg: &OpenClawMessage{
				Type:    "tool",
				Action:  "invalid",
				Payload: map[string]interface{}{"name": "test"},
			},
			wantErr: true,
		},
		{
			name: "missing tool name",
			msg: &OpenClawMessage{
				Type:    "tool",
				Action:  "tool.call",
				Payload: map[string]interface{}{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ParseToolCall(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseToolCall() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseBatch(t *testing.T) {
	p := NewParser()

	// Test batch array
	batchJSON := `[
		{"type": "tool", "action": "tool.call", "payload": {"name": "tool1", "args": {}}},
		{"type": "tool", "action": "tool.call", "payload": {"name": "tool2", "args": {}}}
	]`

	messages, err := p.ParseBatch([]byte(batchJSON))
	if err != nil {
		t.Fatalf("ParseBatch() error = %v", err)
	}
	if len(messages) != 2 {
		t.Errorf("ParseBatch() returned %d messages, want 2", len(messages))
	}

	// Test single message (not array)
	singleJSON := `{"type": "tool", "action": "tool.call", "payload": {"name": "single", "args": {}}}`
	messages, err = p.ParseBatch([]byte(singleJSON))
	if err != nil {
		t.Fatalf("ParseBatch() single error = %v", err)
	}
	if len(messages) != 1 {
		t.Errorf("ParseBatch() single returned %d messages, want 1", len(messages))
	}
}

func TestParseBatch_Invalid(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name:    "empty data",
			json:    "",
			wantErr: true,
		},
		{
			name:    "invalid json",
			json:    `[invalid`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ParseBatch([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseBatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePayload(t *testing.T) {
	p := NewParser()

	payload := map[string]interface{}{
		"name":  "test_tool",
		"value": 123,
	}

	err := p.ValidatePayload(payload, []string{"name", "value"})
	if err != nil {
		t.Errorf("ValidatePayload() unexpected error: %v", err)
	}

	err = p.ValidatePayload(payload, []string{"name", "missing"})
	if err == nil {
		t.Error("ValidatePayload() should fail for missing field")
	}

	err = p.ValidatePayload(nil, []string{"name"})
	if err == nil {
		t.Error("ValidatePayload() should fail for nil payload")
	}
}

func TestToolCall_GetArg(t *testing.T) {
	tc := &ToolCall{
		Name:      "test",
		Args:      map[string]interface{}{"str": "hello", "num": float64(42), "bool": true},
		SessionID: "sess-1",
	}

	// String arg
	v, ok := tc.GetStringArg("str")
	if !ok || v != "hello" {
		t.Errorf("GetStringArg() = %v, %v; want hello, true", v, ok)
	}

	// Int arg
	vInt, ok := tc.GetIntArg("num")
	if !ok || vInt != 42 {
		t.Errorf("GetIntArg() = %v, %v; want 42, true", vInt, ok)
	}

	// Bool arg
	vBool, ok := tc.GetBoolArg("bool")
	if !ok || vBool != true {
		t.Errorf("GetBoolArg() = %v, %v; want true, true", vBool, ok)
	}

	// Missing arg
	_, ok = tc.GetStringArg("missing")
	if ok {
		t.Error("GetStringArg() should return false for missing arg")
	}
}

func TestToolCall_ToJSON(t *testing.T) {
	tc := &ToolCall{
		Name:       "file_read",
		Args:       map[string]interface{}{"path": "/tmp/test.txt"},
		SessionID:  "sess-123",
		ContextID:  "ctx-456",
		ActionType: "tool.call",
	}

	data, err := tc.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Verify it can be parsed back
	var msg OpenClawMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("ToJSON() produced invalid JSON: %v", err)
	}

	if msg.Type != "tool" {
		t.Errorf("Type = %s, want tool", msg.Type)
	}
	if msg.Action != "tool.call" {
		t.Errorf("Action = %s, want tool.call", msg.Action)
	}
}

func TestExtractHelpers(t *testing.T) {
	m := map[string]interface{}{
		"string_val": "hello",
		"map_val":    map[string]interface{}{"nested": "value"},
	}

	if s := extractString(m, "string_val"); s != "hello" {
		t.Errorf("extractString() = %s, want hello", s)
	}
	if s := extractString(m, "missing"); s != "" {
		t.Errorf("extractString() missing = %s, want empty", s)
	}
	if s := extractString(nil, "key"); s != "" {
		t.Errorf("extractString() nil = %s, want empty", s)
	}

	if mp := extractMap(m, "map_val"); mp == nil {
		t.Error("extractMap() returned nil for valid map")
	}
	if mp := extractMap(m, "missing"); mp != nil {
		t.Error("extractMap() should return nil for missing key")
	}
	if mp := extractMap(nil, "key"); mp != nil {
		t.Error("extractMap() should return nil for nil map")
	}
}
