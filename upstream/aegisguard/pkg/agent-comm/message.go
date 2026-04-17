package agentcomm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// simpleUUID generates a simple UUID v4-like string
func simpleUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b)
}

// MessageType defines the type of agent-to-agent message
type MessageType string

const (
	// MessageTypeRequest represents a request message
	MessageTypeRequest MessageType = "request"
	// MessageTypeResponse represents a response to a request
	MessageTypeResponse MessageType = "response"
	// MessageTypeEvent represents an event notification
	MessageTypeEvent MessageType = "event"
	// MessageTypeHeartbeat represents a heartbeat message
	MessageTypeHeartbeat MessageType = "heartbeat"
	// MessageTypeCommand represents a command message
	MessageTypeCommand MessageType = "command"
	// MessageTypeError represents an error message
	MessageTypeError MessageType = "error"
)

// Priority levels for messages
const (
	PriorityLow      = 1
	PriorityNormal   = 5
	PriorityHigh     = 10
	PriorityCritical = 15
)

// Message represents an agent-to-agent message
type Message struct {
	ID          string                 `json:"id"`
	Type        MessageType            `json:"type"`
	Sender      string                 `json:"sender"`
	Recipient   string                 `json:"recipient"`
	Payload     interface{}            `json:"payload"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Priority    int                    `json:"priority"`
	Timestamp   time.Time              `json:"timestamp"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	ReplyTo     string                 `json:"reply_to,omitempty"`
	Correlation string                 `json:"correlation_id,omitempty"`
}

// NewMessage creates a new message with generated ID and timestamp
func NewMessage(msgType MessageType, sender, recipient string, payload interface{}) *Message {
	return &Message{
		ID:        simpleUUID(),
		Type:      msgType,
		Sender:    sender,
		Recipient: recipient,
		Payload:   payload,
		Metadata:  make(map[string]interface{}),
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
	}
}

// IsExpired checks if the message has expired
func (m *Message) IsExpired() bool {
	if m.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*m.ExpiresAt)
}

// SetExpiry sets expiration time for the message
func (m *Message) SetExpiry(duration time.Duration) {
	expires := time.Now().Add(duration)
	m.ExpiresAt = &expires
}

// Request represents a request message with expected response handling
type Request struct {
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Timeout    time.Duration          `json:"timeout,omitempty"`
}

// Response represents a response to a request
type Response struct {
	Success  bool                   `json:"success"`
	Result   interface{}            `json:"result,omitempty"`
	Error    *ResponseError         `json:"error,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ResponseError contains error information
type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Cause   error  `json:"-"`
}

// Error implements the error interface
func (e *ResponseError) Error() string {
	return e.Message
}

// Unwrap returns the underlying cause
func (e *ResponseError) Unwrap() error {
	return e.Cause
}

// NewResponse creates a successful response
func NewResponse(result interface{}) *Response {
	return &Response{
		Success: true,
		Result:  result,
	}
}

// NewErrorResponse creates an error response
func NewErrorResponse(code, message string, cause error) *Response {
	return &Response{
		Success: false,
		Error:   &ResponseError{Code: code, Message: message, Cause: cause},
	}
}

// Event represents an event notification
type Event struct {
	Name      string                 `json:"name"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// NewEvent creates a new event
func NewEvent(name, source string, data map[string]interface{}) *Event {
	return &Event{
		Name:      name,
		Source:    source,
		Data:      data,
		Timestamp: time.Now(),
	}
}

// Command represents a command from a controller
type Command struct {
	Name       string                 `json:"name"`
	Parameters map[string]interface{} `json:"parameters"`
	IssuedAt   time.Time              `json:"issued_at"`
}

// NewCommand creates a new command
func NewCommand(name string, params map[string]interface{}) *Command {
	return &Command{
		Name:       name,
		Parameters: params,
		IssuedAt:   time.Now(),
	}
}

// Heartbeat represents a heartbeat message for agent liveness
type Heartbeat struct {
	AgentID     string    `json:"agent_id"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
	Capabiliies []string  `json:"capabilities,omitempty"`
	Load        float64   `json:"load,omitempty"`
}

// NewHeartbeat creates a new heartbeat
func NewHeartbeat(agentID, status string) *Heartbeat {
	return &Heartbeat{
		AgentID:   agentID,
		Status:    status,
		Timestamp: time.Now(),
	}
}

// Errors
var (
	ErrInvalidMessage = errors.New("invalid message")
	ErrChannelClosed  = errors.New("channel closed")
	ErrTimeout        = errors.New("operation timed out")
	ErrAgentNotFound  = errors.New("agent not found")
	ErrInvalidAgentID = errors.New("invalid agent ID")
	ErrChannelFull    = errors.New("channel full")
	ErrNotRecipient   = errors.New("message recipient does not match")
)
