// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — SSE Streaming Performance Benchmarks

package soc

import (
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
)

func BenchmarkPushEvent(b *testing.B) {
	streamer := NewTimelineStreamer(nil, StreamConfig{BufferSize: 64})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := correlation.NewEvent("http", "prompt_injection", "bench-agent", "bench-session")
		streamer.PushEvent(event)
	}
}

func BenchmarkTimelineStreamer(b *testing.B) {
	streamer := NewTimelineStreamer(nil, StreamConfig{BufferSize: 64})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := correlation.NewEvent("mcp", "tool_execution", "bench-agent", "bench-session")
		streamer.PushEvent(event)
	}
}

func BenchmarkStreamEventConversion(b *testing.B) {
	events := make([]*correlation.Event, 100)
	for i := range events {
		events[i] = correlation.NewEvent("http", "prompt_injection", "bench-agent", "bench-session")
		events[i].Severity = "high"
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, event := range events {
			convertEvent(event)
		}
	}
}

func BenchmarkSubscribeAndPush(b *testing.B) {
	streamer := NewTimelineStreamer(nil, StreamConfig{BufferSize: 64})

	// Subscribe a client
	ch := streamer.Subscribe("bench-client")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := correlation.NewEvent("http", "prompt_injection", "bench-agent", "bench-session")
		streamer.PushEvent(event)
		// Drain the channel
		select {
		case <-ch:
		default:
		}
	}
	_ = time.Now() // prevent unused import
}
