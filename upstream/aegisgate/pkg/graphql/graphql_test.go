package graphql

import (
	"context"
	"testing"
)

func TestNewExecutor(t *testing.T) {
	resolver := &Resolver{}
	exec := NewExecutor(resolver)
	if exec == nil {
		t.Fatal("NewExecutor returned nil")
	}
	if exec.resolver != resolver {
		t.Error("resolver not set correctly")
	}
}

func TestExecutorExecute(t *testing.T) {
	resolver := &Resolver{}
	exec := NewExecutor(resolver)
	ctx := context.Background()

	// Test simple query
	resp := exec.Execute(ctx, `query { health }`, nil)
	if resp == nil {
		t.Fatal("Execute returned nil")
	}
}

func TestExecutorParse(t *testing.T) {
	resolver := &Resolver{}
	exec := NewExecutor(resolver)

	// Test parsing with valid GraphQL-like query
	doc, err := exec.parse(`query { health }`)
	if err != nil {
		t.Errorf("parse error: %v", err)
	}
	if doc == nil {
		t.Error("document is nil")
	}
}

func TestResponse(t *testing.T) {
	resp := &Response{
		Data:   map[string]interface{}{"key": "value"},
		Errors: []*Error{{Message: "test error"}},
	}

	if resp.Data == nil {
		t.Error("Data should not be nil")
	}
	if len(resp.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(resp.Errors))
	}
}

func TestError(t *testing.T) {
	err := &Error{
		Message:   "test error",
		Locations: []Location{{Line: 1, Column: 1}},
		Path:      []interface{}{"root", "field"},
	}

	if err.Message != "test error" {
		t.Errorf("expected message 'test error', got %s", err.Message)
	}
	if len(err.Locations) != 1 {
		t.Errorf("expected 1 location, got %d", len(err.Locations))
	}
}

func TestDocument(t *testing.T) {
	doc := &document{
		Operations: map[string]*operation{
			"testOp": {
				Name:         "testOp",
				SelectionSet: []selection{{Name: "field1"}},
			},
		},
	}

	if doc.Operations["testOp"] == nil {
		t.Error("operation not set")
	}
	if len(doc.Operations["testOp"].SelectionSet) != 1 {
		t.Error("selection set not set correctly")
	}
}
