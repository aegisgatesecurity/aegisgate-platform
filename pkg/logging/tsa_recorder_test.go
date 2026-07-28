// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - TSA Recording Wrapper Tests (v3.5.0+)
// =========================================================================

package logging

import (
	"sync"
	"testing"
	"time"
)

// mockSigner is a mock AuditEventSigner for testing.
type mockSigner struct {
	mu        sync.Mutex
	calls     int
	fail      bool
	endpoints []string
	signed    []*AuditEventSigned
}

func (m *mockSigner) SignAuditEvent(eventID string, data []byte) (*AuditEventSigned, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.fail {
		return nil, &mockTSAError{msg: "mock TSA failure"}
	}
	signed := &AuditEventSigned{
		EventID:     eventID,
		DataHash:    make([]byte, 32),
		Verified:    true,
		GenTime:     time.Now().UTC(),
		TSAEndpoint: "https://tsa.example.com",
	}
	m.signed = append(m.signed, signed)
	return signed, nil
}

func (m *mockSigner) Endpoints() []string {
	return m.endpoints
}

func (m *mockSigner) getCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type mockTSAError struct {
	msg string
}

func (e *mockTSAError) Error() string {
	return e.msg
}

// TestTSARecordingWrapper_NilSigner_Passthrough tests that when the
// TSA signer is nil, events pass through unchanged.
func TestTSARecordingWrapper_NilSigner_Passthrough(t *testing.T) {
	ring := NewRingBuffer(100)
	wrapper := NewTSARecordingWrapper(ring, nil)

	evt := Event{
		Type:     "auth",
		Severity: SeverityInfo,
		Message:  "test event",
	}

	wrapper.Add(evt)

	if ring.Size() != 1 {
		t.Fatalf("expected ring size 1, got %d", ring.Size())
	}

	events := ring.SnapshotBetween(time.Time{}, time.Now().Add(time.Hour))
	if events[0].TSA != nil {
		t.Error("expected nil TSA field when signer is nil")
	}
}

// TestTSARecordingWrapper_SuccessfulTimestamp tests that when TSA
// timestamping succeeds, the event has TSA data attached.
func TestTSARecordingWrapper_SuccessfulTimestamp(t *testing.T) {
	ring := NewRingBuffer(100)
	mock := &mockSigner{
		endpoints: []string{"https://tsa.example.com"},
	}

	wrapper := NewTSARecordingWrapper(ring, mock)

	evt := Event{
		ID:       "test-event-1",
		Type:     "threat",
		Severity: SeverityHigh,
		Message:  "jailbreak attempt detected",
	}

	wrapper.Add(evt)

	if ring.Size() != 1 {
		t.Fatalf("expected ring size 1, got %d", ring.Size())
	}

	events := ring.SnapshotBetween(time.Time{}, time.Now().Add(time.Hour))
	if events[0].TSA == nil {
		t.Fatal("expected TSA data on event, got nil")
	}
	if events[0].TSA.EventID != "test-event-1" {
		t.Errorf("expected TSA event ID test-event-1, got %s", events[0].TSA.EventID)
	}
	if !events[0].TSA.Verified {
		t.Error("expected TSA verified=true")
	}
	if events[0].TSA.TSAEndpoint != "https://tsa.example.com" {
		t.Errorf("expected TSA endpoint, got %s", events[0].TSA.TSAEndpoint)
	}

	signed, failed := wrapper.Stats()
	if signed != 1 {
		t.Errorf("expected 1 signed event, got %d", signed)
	}
	if failed != 0 {
		t.Errorf("expected 0 failed events, got %d", failed)
	}
}

// TestTSARecordingWrapper_FailureDegradation tests that when TSA
// timestamping fails, the event is still recorded without TSA data.
func TestTSARecordingWrapper_FailureDegradation(t *testing.T) {
	ring := NewRingBuffer(100)
	mock := &mockSigner{
		fail:      true,
		endpoints: []string{"https://tsa.example.com"},
	}

	wrapper := NewTSARecordingWrapper(ring, mock)

	evt := Event{
		ID:       "test-failure",
		Type:     "auth",
		Severity: SeverityInfo,
		Message:  "test event",
	}

	wrapper.Add(evt)

	if ring.Size() != 1 {
		t.Fatalf("expected ring size 1, got %d", ring.Size())
	}

	events := ring.SnapshotBetween(time.Time{}, time.Now().Add(time.Hour))
	if events[0].TSA != nil {
		t.Error("expected nil TSA field when signing fails")
	}

	signed, failed := wrapper.Stats()
	if signed != 0 {
		t.Errorf("expected 0 signed events, got %d", signed)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed event, got %d", failed)
	}
}

// TestTSARecordingWrapper_Stats tests the Stats() method.
func TestTSARecordingWrapper_Stats(t *testing.T) {
	ring := NewRingBuffer(100)
	wrapper := NewTSARecordingWrapper(ring, nil)

	signed, failed := wrapper.Stats()
	if signed != 0 || failed != 0 {
		t.Errorf("expected initial stats (0, 0), got (%d, %d)", signed, failed)
	}
}

// TestTSARecordingWrapper_Disable tests that Disable() stops TSA
// timestamping even with a valid signer.
func TestTSARecordingWrapper_Disable(t *testing.T) {
	ring := NewRingBuffer(100)
	mock := &mockSigner{
		endpoints: []string{"https://tsa.example.com"},
	}

	wrapper := NewTSARecordingWrapper(ring, mock)

	if !wrapper.enabled.Load() {
		t.Error("wrapper should be enabled with valid signer")
	}

	wrapper.Disable()

	if wrapper.enabled.Load() {
		t.Error("wrapper should be disabled after Disable()")
	}

	// After disabling, events should pass through without TSA.
	evt := Event{
		ID:       "test-after-disable",
		Type:     "auth",
		Severity: SeverityInfo,
		Message:  "test event",
	}
	wrapper.Add(evt)

	events := ring.SnapshotBetween(time.Time{}, time.Now().Add(time.Hour))
	if events[0].TSA != nil {
		t.Error("expected nil TSA after disable")
	}
}

// TestTSARecordingWrapper_EventIDGeneration tests that events without
// an ID get a generated one before TSA signing.
func TestTSARecordingWrapper_EventIDGeneration(t *testing.T) {
	ring := NewRingBuffer(100)
	mock := &mockSigner{
		endpoints: []string{"https://tsa.example.com"},
	}

	wrapper := NewTSARecordingWrapper(ring, mock)

	evt := Event{
		Type:     "auth",
		Severity: SeverityInfo,
		Message:  "test without ID",
		// ID is intentionally empty
	}

	wrapper.Add(evt)

	if ring.Size() != 1 {
		t.Fatalf("expected ring size 1, got %d", ring.Size())
	}

	events := ring.SnapshotBetween(time.Time{}, time.Now().Add(time.Hour))
	// The event should have an ID generated by the wrapper.
	if events[0].ID == "" {
		t.Error("expected non-empty event ID after wrapper processing")
	}
	// The TSA data should have the generated event ID.
	if events[0].TSA == nil {
		t.Fatal("expected TSA data on event")
	}
	if events[0].TSA.EventID == "" {
		t.Error("expected non-empty TSA event ID")
	}
}

// TestTSARecordingWrapper_ConcurrentAdd tests that concurrent Add()
// calls are safe.
func TestTSARecordingWrapper_ConcurrentAdd(t *testing.T) {
	ring := NewRingBuffer(1000)
	mock := &mockSigner{
		endpoints: []string{"https://tsa.example.com"},
	}
	wrapper := NewTSARecordingWrapper(ring, mock)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wrapper.Add(Event{
				ID:       time.Now().Format("20060102150405"),
				Type:     "concurrent",
				Severity: SeverityInfo,
				Message:  "concurrent test",
			})
		}()
	}
	wg.Wait()

	if ring.Size() != 50 {
		t.Errorf("expected ring size 50, got %d", ring.Size())
	}

	signed, failed := wrapper.Stats()
	if signed != 50 {
		t.Errorf("expected 50 signed events, got %d", signed)
	}
	if failed != 0 {
		t.Errorf("expected 0 failed events, got %d", failed)
	}
}

// TestGenerateEventID tests the event ID generation helper.
func TestGenerateEventID(t *testing.T) {
	evt := Event{
		Type:     "auth",
		Severity: SeverityInfo,
		Time:     time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}

	id := generateEventID(&evt)
	if id == "" {
		t.Error("expected non-empty event ID")
	}
	if id[:5] != "auth-" {
		t.Errorf("expected ID to start with 'auth-', got %s", id[:5])
	}
}

// TestEventTSA_JSONRoundTrip tests that EventTSA serializes correctly.
func TestEventTSA_JSONRoundTrip(t *testing.T) {
	ts := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	eventTSA := &EventTSA{
		EventID:     "test-123",
		DataHash:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Timestamp:   ts,
		TSAEndpoint: "https://tsa.example.com",
		Verified:    true,
	}

	evt := Event{
		ID:       "test-event",
		Type:     "threat",
		Severity: SeverityHigh,
		Message:  "jailbreak detected",
		TSA:      eventTSA,
	}

	// Verify the event has TSA data.
	if evt.TSA == nil {
		t.Fatal("expected TSA data on event")
	}
	if evt.TSA.EventID != "test-123" {
		t.Errorf("expected TSA event ID test-123, got %s", evt.TSA.EventID)
	}
	if !evt.TSA.Verified {
		t.Error("expected TSA verified=true")
	}
	if evt.TSA.TSAEndpoint != "https://tsa.example.com" {
		t.Errorf("expected TSA endpoint, got %s", evt.TSA.TSAEndpoint)
	}
	if evt.TSA.Timestamp.IsZero() {
		t.Error("expected non-zero TSA timestamp")
	}
}