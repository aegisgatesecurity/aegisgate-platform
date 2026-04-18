package grpc

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestNewServer(t *testing.T) {
	logger := slog.Default()
	server := NewServer(":50051", logger)
	if server == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestStartStop(t *testing.T) {
	logger := slog.Default()
	port := ":50053"

	server, err := Start(port, logger)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	Stop(server)
}

func TestStopNil(t *testing.T) {
	// Should not panic
	Stop(nil)
}

func TestUnaryInterceptor(t *testing.T) {
	logger := slog.Default()
	interceptor := UnaryInterceptor(logger)

	if interceptor == nil {
		t.Fatal("UnaryInterceptor returned nil")
	}

	// Test that it's a valid interceptor
	ctx := context.Background()

	// Create a minimal handler
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test/Test",
		Server:     nil,
	}

	resp, err := interceptor(ctx, "request", info, handler)
	if err != nil {
		t.Errorf("interceptor error: %v", err)
	}
	if resp != "response" {
		t.Errorf("expected response, got %v", resp)
	}
}

func TestStreamInterceptor(t *testing.T) {
	logger := slog.Default()
	interceptor := StreamInterceptor(logger)

	if interceptor == nil {
		t.Fatal("StreamInterceptor returned nil")
	}
}

func TestRunServer(t *testing.T) {
	logger := slog.Default()
	port := ":50054"

	// Run in goroutine to avoid blocking
	go func() {
		err := RunServer(port, logger)
		if err != nil {
			t.Logf("RunServer error (expected on termination): %v", err)
		}
	}()

	// Let it start
	time.Sleep(100 * time.Millisecond)
}
