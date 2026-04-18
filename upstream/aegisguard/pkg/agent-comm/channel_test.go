package agentcomm

import (
	"context"
	"testing"
	"time"
)

func TestNewChannel(t *testing.T) {
	ch, err := NewChannel("test-channel")
	if err != nil {
		t.Fatalf("NewChannel() error = %v", err)
	}
	if ch == nil {
		t.Fatal("NewChannel() returned nil")
	}
	if ch.Name() != "test-channel" {
		t.Errorf("Name() = %s, want test-channel", ch.Name())
	}
}

func TestNewChannelEmptyName(t *testing.T) {
	_, err := NewChannel("")
	if err == nil {
		t.Error("Expected error for empty channel name")
	}
}

func TestChannelSubscribe(t *testing.T) {
	ch, _ := NewChannel("test")

	err := ch.Subscribe("agent1")
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	if !ch.IsSubscribed("agent1") {
		t.Error("IsSubscribed() should return true")
	}
}

func TestChannelUnsubscribe(t *testing.T) {
	ch, _ := NewChannel("test")
	ch.Subscribe("agent1")

	ch.Unsubscribe("agent1")

	if ch.IsSubscribed("agent1") {
		t.Error("IsSubscribed() should return false after unsubscribe")
	}
}

func TestChannelSubscribers(t *testing.T) {
	ch, _ := NewChannel("test")
	ch.Subscribe("agent1")
	ch.Subscribe("agent2")

	subs := ch.Subscribers()
	if len(subs) != 2 {
		t.Errorf("Subscribers() count = %d, want 2", len(subs))
	}
}

func TestChannelSend(t *testing.T) {
	ch, _ := NewChannel("test")
	ch.Subscribe("agent1")

	msg := NewMessage(MessageTypeRequest, "sender", "agent1", "test payload")
	err := ch.Send(msg)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestChannelReceive(t *testing.T) {
	ch, _ := NewChannel("test")
	ch.Subscribe("agent1")

	msg := NewMessage(MessageTypeRequest, "sender", "agent1", "test payload")
	ch.Send(msg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	received, err := ch.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if received.Payload != "test payload" {
		t.Errorf("Payload = %v, want test payload", received.Payload)
	}
}

func TestChannelReceiveTimeout(t *testing.T) {
	ch, _ := NewChannel("test")

	_, err := ch.ReceiveTimeout(50 * time.Millisecond)
	if err != context.DeadlineExceeded {
		t.Errorf("Expected timeout error, got %v", err)
	}
}

func TestChannelPeek(t *testing.T) {
	ch, _ := NewChannel("test")
	ch.Subscribe("agent1")

	ch.Send(NewMessage(MessageTypeRequest, "s1", "a1", "msg1"))
	ch.Send(NewMessage(MessageTypeRequest, "s2", "a1", "msg2"))

	msgs := ch.Peek()
	if len(msgs) != 2 {
		t.Errorf("Peek() count = %d, want 2", len(msgs))
	}
}

func TestChannelGetMessages(t *testing.T) {
	ch, _ := NewChannel("test")

	ch.Send(NewMessage(MessageTypeRequest, "s1", "agent1", "msg1"))
	ch.Send(NewMessage(MessageTypeRequest, "s2", "agent2", "msg2"))
	ch.Send(NewMessage(MessageTypeRequest, "s3", "agent1", "msg3"))

	msgs := ch.GetMessages("agent1")
	if len(msgs) != 2 {
		t.Errorf("GetMessages(agent1) = %d, want 2", len(msgs))
	}
}

func TestChannelClose(t *testing.T) {
	ch, _ := NewChannel("test")

	err := ch.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if !ch.IsClosed() {
		t.Error("IsClosed() should return true")
	}
}

func TestChannelMessageCount(t *testing.T) {
	ch, _ := NewChannel("test")
	ch.Subscribe("agent1")

	ch.Send(NewMessage(MessageTypeRequest, "s1", "a1", "msg1"))
	ch.Send(NewMessage(MessageTypeRequest, "s2", "a1", "msg2"))

	if ch.MessageCount() != 2 {
		t.Errorf("MessageCount() = %d, want 2", ch.MessageCount())
	}
}

func TestChannelClear(t *testing.T) {
	ch, _ := NewChannel("test")
	ch.Subscribe("agent1")

	ch.Send(NewMessage(MessageTypeRequest, "s1", "a1", "msg1"))
	ch.Clear()

	if ch.MessageCount() != 0 {
		t.Error("MessageCount() should be 0 after clear")
	}
}

func TestNewMessage(t *testing.T) {
	msg := NewMessage(MessageTypeRequest, "sender", "recipient", "payload")

	if msg.Type != MessageTypeRequest {
		t.Errorf("Type = %v, want MessageTypeRequest", msg.Type)
	}
	if msg.Sender != "sender" {
		t.Errorf("Sender = %s, want sender", msg.Sender)
	}
	if msg.Recipient != "recipient" {
		t.Errorf("Recipient = %s, want recipient", msg.Recipient)
	}
	if msg.Payload != "payload" {
		t.Errorf("Payload = %v, want payload", msg.Payload)
	}
	if msg.ID == "" {
		t.Error("ID should not be empty")
	}
	if msg.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestMessageIsExpired(t *testing.T) {
	msg := NewMessage(MessageTypeRequest, "s", "r", nil)

	if msg.IsExpired() {
		t.Error("Message should not be expired initially")
	}

	msg.SetExpiry(-time.Hour)
	if !msg.IsExpired() {
		t.Error("Message should be expired")
	}
}

func TestMessageSetExpiry(t *testing.T) {
	msg := NewMessage(MessageTypeRequest, "s", "r", nil)
	msg.SetExpiry(time.Hour)

	if msg.ExpiresAt == nil {
		t.Fatal("ExpiresAt should be set")
	}
	if time.Now().Add(time.Hour).Before(*msg.ExpiresAt) {
		t.Error("Expiry time not in expected range")
	}
}

func TestNewResponse(t *testing.T) {
	resp := NewResponse("result")

	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.Result != "result" {
		t.Errorf("Result = %v, want result", resp.Result)
	}
}

func TestNewErrorResponse(t *testing.T) {
	resp := NewErrorResponse("ERR_CODE", "error message", nil)

	if resp.Success {
		t.Error("Success should be false")
	}
	if resp.Error == nil {
		t.Fatal("Error should not be nil")
	}
	if resp.Error.Code != "ERR_CODE" {
		t.Errorf("Error code = %s, want ERR_CODE", resp.Error.Code)
	}
}

func TestNewEvent(t *testing.T) {
	event := NewEvent("test.event", "source", map[string]interface{}{"key": "value"})

	if event.Name != "test.event" {
		t.Errorf("Name = %s, want test.event", event.Name)
	}
	if event.Source != "source" {
		t.Errorf("Source = %s, want source", event.Source)
	}
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestNewCommand(t *testing.T) {
	cmd := NewCommand("stop", map[string]interface{}{"force": true})

	if cmd.Name != "stop" {
		t.Errorf("Name = %s, want stop", cmd.Name)
	}
	if cmd.IssuedAt.IsZero() {
		t.Error("IssuedAt should not be zero")
	}
}

func TestNewHeartbeat(t *testing.T) {
	hb := NewHeartbeat("agent1", "healthy")

	if hb.AgentID != "agent1" {
		t.Errorf("AgentID = %s, want agent1", hb.AgentID)
	}
	if hb.Status != "healthy" {
		t.Errorf("Status = %s, want healthy", hb.Status)
	}
	if hb.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestChannelClosedReceive(t *testing.T) {
	ch, _ := NewChannel("test")
	ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := ch.Receive(ctx)
	if err != ErrChannelClosed {
		t.Errorf("Expected ErrChannelClosed, got %v", err)
	}
}

func TestChannelPriority(t *testing.T) {
	ch, _ := NewChannel("test", WithPriorityAware(true))
	ch.Subscribe("agent1")

	// Send low priority first
	msg1 := NewMessage(MessageTypeRequest, "s1", "agent1", "low")
	msg1.Priority = PriorityLow
	ch.Send(msg1)

	// Send high priority
	msg2 := NewMessage(MessageTypeRequest, "s2", "agent1", "high")
	msg2.Priority = PriorityHigh
	ch.Send(msg2)

	// Verify messages are stored in priority order (high first)
	msgs := ch.Peek()
	if len(msgs) != 2 {
		t.Fatalf("Expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].Priority != PriorityHigh {
		t.Errorf("First message priority = %d, want %d (High)", msgs[0].Priority, PriorityHigh)
	}
	if msgs[1].Priority != PriorityLow {
		t.Errorf("Second message priority = %d, want %d (Low)", msgs[1].Priority, PriorityLow)
	}
}
