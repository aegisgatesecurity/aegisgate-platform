package immutableconfig

import (
	"testing"
)

func TestNewConfigData(t *testing.T) {
	data := make(map[string]interface{})
	data["key"] = "value"

	metadata := make(map[string]string)
	metadata["author"] = "test"

	config := NewConfigData("v1.0", data, metadata)

	if config.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", config.Version)
	}

	if config.Data["key"] != "value" {
		t.Errorf("Expected data key to be value, got %v", config.Data["key"])
	}
}

func TestValidate(t *testing.T) {
	config := NewConfigData("v1.0", nil, nil)

	if err := config.Validate(); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestValidateEmptyVersion(t *testing.T) {
	config := &ConfigData{
		Version: "",
		Data:    make(map[string]interface{}),
	}

	if err := config.Validate(); err == nil {
		t.Errorf("Expected error for empty version")
	}
}

func TestGet(t *testing.T) {
	data := make(map[string]interface{})
	data["key"] = "value"

	config := NewConfigData("v1.0", data, nil)

	value, exists := config.Get("key")
	if !exists {
		t.Errorf("Expected key to exist")
	}
	if value != "value" {
		t.Errorf("Expected value to be value, got %v", value)
	}

	_, exists = config.Get("nonexistent")
	if exists {
		t.Errorf("Expected nonexistent key to not exist")
	}
}

func TestSet(t *testing.T) {
	config := NewConfigData("v1.0", nil, nil)

	config.Set("newkey", "newvalue")

	value, exists := config.Get("newkey")
	if !exists {
		t.Errorf("Expected newkey to exist")
	}
	if value != "newvalue" {
		t.Errorf("Expected value to be newvalue, got %v", value)
	}
}

func TestString(t *testing.T) {
	config := NewConfigData("v1.0", nil, nil)

	str := config.String()
	if str == "" {
		t.Errorf("Expected non-empty string")
	}
}

func TestNewConfigVersion(t *testing.T) {
	version := NewConfigVersion("v1.0", "abc123")

	if version.Version != "v1.0" {
		t.Errorf("Expected version v1.0, got %s", version.Version)
	}
	if version.Hash != "abc123" {
		t.Errorf("Expected hash abc123, got %s", version.Hash)
	}
}

func TestConfigDataString(t *testing.T) {
	config := NewConfigData("test", map[string]interface{}{"test": "value"}, map[string]string{"author": "test"})

	str := config.String()
	if str == "" {
		t.Errorf("Expected non-empty string representation")
	}
}

func TestConfigVersionString(t *testing.T) {
	version := NewConfigVersion("v1.0", "abc123def456ghij")

	if len(version.Hash) != 16 {
		t.Errorf("Expected truncated hash length 16, got %d", len(version.Hash))
	}
}
