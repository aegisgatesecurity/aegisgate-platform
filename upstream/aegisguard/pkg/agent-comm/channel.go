package agentcomm

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Channel represents a communication channel for agent messaging
type Channel struct {
	id         string
	name       string
	agents     map[string]bool
	mu         sync.RWMutex
	messages   []*Message
	subscriber chan *Message
	closed     bool
	opts       *ChannelOptions
}

// ChannelOptions configures channel behavior
type ChannelOptions struct {
	MaxMessages    int
	MaxSubscribers int
	Broadcast      bool
	PriorityAware  bool
}

// DefaultChannelOptions returns sensible defaults
func DefaultChannelOptions() *ChannelOptions {
	return &ChannelOptions{
		MaxMessages:    1000,
		MaxSubscribers: 100,
		Broadcast:      false,
		PriorityAware:  true,
	}
}

// NewChannel creates a new communication channel
func NewChannel(name string, opts ...ChannelOption) (*Channel, error) {
	if name == "" {
		return nil, errors.New("channel name cannot be empty")
	}

	options := DefaultChannelOptions()
	for _, opt := range opts {
		opt(options)
	}

	return &Channel{
		id:         simpleUUID(),
		name:       name,
		agents:     make(map[string]bool),
		messages:   make([]*Message, 0, options.MaxMessages),
		subscriber: make(chan *Message, options.MaxMessages),
		closed:     false,
		opts:       options,
	}, nil
}

// ChannelOption functional option for channel configuration
type ChannelOption func(*ChannelOptions)

// WithMaxMessages sets maximum message storage
func WithMaxMessages(max int) ChannelOption {
	return func(o *ChannelOptions) {
		o.MaxMessages = max
	}
}

// WithBroadcast enables broadcast mode
func WithBroadcast(enabled bool) ChannelOption {
	return func(o *ChannelOptions) {
		o.Broadcast = enabled
	}
}

// WithPriorityAware enables priority-based message delivery
func WithPriorityAware(enabled bool) ChannelOption {
	return func(o *ChannelOptions) {
		o.PriorityAware = enabled
	}
}

// ID returns the channel ID
func (c *Channel) ID() string {
	return c.id
}

// Name returns the channel name
func (c *Channel) Name() string {
	return c.name
}

// Subscribe registers an agent to receive messages on this channel
func (c *Channel) Subscribe(agentID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrChannelClosed
	}
	if c.opts.MaxSubscribers > 0 && len(c.agents) >= c.opts.MaxSubscribers {
		return errors.New("maximum subscribers reached")
	}
	c.agents[agentID] = true
	return nil
}

// Unsubscribe removes an agent from the channel
func (c *Channel) Unsubscribe(agentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.agents, agentID)
}

// IsSubscribed checks if an agent is subscribed
func (c *Channel) IsSubscribed(agentID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.agents[agentID]
}

// Subscribers returns list of subscribed agent IDs
func (c *Channel) Subscribers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	subs := make([]string, 0, len(c.agents))
	for id := range c.agents {
		subs = append(subs, id)
	}
	return subs
}

// Send adds a message to the channel
func (c *Channel) Send(msg *Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrChannelClosed
	}

	if c.opts.PriorityAware && msg.Priority > PriorityNormal {
		// Insert message at appropriate position based on priority
		inserted := false
		for i, m := range c.messages {
			if msg.Priority > m.Priority {
				c.messages = append(c.messages[:i], append([]*Message{msg}, c.messages[i:]...)...)
				inserted = true
				break
			}
		}
		if !inserted {
			c.messages = append(c.messages, msg)
		}
	} else {
		c.messages = append(c.messages, msg)
	}

	// Trim if over max
	if c.opts.MaxMessages > 0 && len(c.messages) > c.opts.MaxMessages {
		c.messages = c.messages[len(c.messages)-c.opts.MaxMessages:]
	}

	select {
	case c.subscriber <- msg:
	default:
		// Channel buffer full, message still stored
	}

	return nil
}

// Receive waits for a message on the channel
func (c *Channel) Receive(ctx context.Context) (*Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg, ok := <-c.subscriber:
		if !ok {
			return nil, ErrChannelClosed
		}
		return msg, nil
	}
}

// ReceiveTimeout receives with timeout
func (c *Channel) ReceiveTimeout(timeout time.Duration) (*Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.Receive(ctx)
}

// Peek returns all messages without removing them
func (c *Channel) Peek() []*Message {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*Message, len(c.messages))
	copy(result, c.messages)
	return result
}

// GetMessages returns messages for a specific recipient
func (c *Channel) GetMessages(agentID string) []*Message {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*Message
	for _, m := range c.messages {
		if m.Recipient == "" || m.Recipient == agentID {
			result = append(result, m)
		}
	}
	return result
}

// Close closes the channel
func (c *Channel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.subscriber)
	return nil
}

// IsClosed checks if channel is closed
func (c *Channel) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// MessageCount returns number of messages in channel
func (c *Channel) MessageCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.messages)
}

// Clear removes all messages from the channel
func (c *Channel) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.messages = c.messages[:0]
}
