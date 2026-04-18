package examples

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/plugin"
)

func TestExampleFilterPlugin_Metadata(t *testing.T) {
	p := NewExampleFilterPlugin()

	metadata := p.Metadata()

	if metadata.ID == "" {
		t.Error("Metadata ID should not be empty")
	}

	if metadata.Name == "" {
		t.Error("Metadata Name should not be empty")
	}

	if metadata.Type != plugin.TypeFilter {
		t.Errorf("Expected TypeFilter, got %v", metadata.Type)
	}
}

func TestExampleFilterPlugin_Init(t *testing.T) {
	p := NewExampleFilterPlugin()
	ctx := context.Background()

	config := plugin.PluginConfig{
		Settings: map[string]interface{}{
			"logLevel": "debug",
		},
	}

	err := p.Init(ctx, config)
	if err != nil {
		t.Errorf("Init failed: %v", err)
	}
}

func TestExampleFilterPlugin_Stats(t *testing.T) {
	p := NewExampleFilterPlugin()

	if p.stats == nil {
		t.Error("Stats should be initialized")
	}

	if p.stats.RequestsProcessed != 0 {
		t.Errorf("Expected initial RequestsProcessed 0, got %d", p.stats.RequestsProcessed)
	}

	if p.stats.ResponsesProcessed != 0 {
		t.Errorf("Expected initial ResponsesProcessed 0, got %d", p.stats.ResponsesProcessed)
	}
}
