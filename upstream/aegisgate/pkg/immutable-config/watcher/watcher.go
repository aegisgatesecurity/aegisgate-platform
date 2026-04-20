// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package watcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType defines types of file events
type EventType string

const (
	EventCreated   EventType = "created"
	EventModified  EventType = "modified"
	EventDeleted   EventType = "deleted"
	EventRenamed   EventType = "renamed"
	EventPermError EventType = "perm_error"
)

// Event represents a file change event
type Event struct {
	Type        EventType `json:"type"`
	Path        string    `json:"path"`
	OldPath     string    `json:"old_path,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Checksum    string    `json:"checksum,omitempty"`
	OldChecksum string    `json:"old_checksum,omitempty"`
	Size        int64     `json:"size,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// Handler is called when an event occurs
type Handler func(event Event)

// Watcher monitors file changes for unauthorized modifications
type Watcher struct {
	mu          sync.RWMutex
	basePath    string
	interval    time.Duration
	handlers    []Handler
	checksums   map[string]string
	running     bool
	stopCh      chan struct{}
	ignorePaths map[string]bool
}

// WatcherOptions for configuring the watcher
type WatcherOptions struct {
	BasePath    string
	Interval    time.Duration
	IgnorePaths []string
}

// DefaultWatcherOptions returns default watcher options
func DefaultWatcherOptions() *WatcherOptions {
	return &WatcherOptions{
		Interval: 5 * time.Second,
	}
}

// NewWatcher creates a new file watcher
func NewWatcher(opts *WatcherOptions) (*Watcher, error) {
	if opts == nil {
		opts = DefaultWatcherOptions()
	}

	if opts.Interval == 0 {
		opts.Interval = 5 * time.Second
	}

	watcher := &Watcher{
		basePath:    opts.BasePath,
		interval:    opts.Interval,
		handlers:    make([]Handler, 0),
		checksums:   make(map[string]string),
		stopCh:      make(chan struct{}),
		ignorePaths: make(map[string]bool),
	}

	// Add ignore paths
	for _, path := range opts.IgnorePaths {
		watcher.ignorePaths[path] = true
	}

	// Initialize checksums
	if opts.BasePath != "" {
		if err := watcher.initializeChecksums(); err != nil {
			return nil, fmt.Errorf("failed to initialize checksums: %w", err)
		}
	}

	return watcher, nil
}

// AddHandler adds an event handler
func (w *Watcher) AddHandler(handler Handler) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handlers = append(w.handlers, handler)
}

// Start starts the watcher
func (w *Watcher) Start() error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("watcher is already running")
	}
	w.running = true
	w.mu.Unlock()

	go w.watchLoop()
	return nil
}

// Stop stops the watcher
func (w *Watcher) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return nil
	}

	close(w.stopCh)
	w.running = false
	return nil
}

// IsRunning returns whether the watcher is running
func (w *Watcher) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

// Scan performs a single scan and returns detected changes
func (w *Watcher) Scan() ([]Event, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	events := make([]Event, 0)

	if w.basePath == "" {
		return events, nil
	}

	err := filepath.Walk(w.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			events = append(events, Event{
				Type:      EventPermError,
				Path:      path,
				Timestamp: time.Now().UTC(),
				Error:     err.Error(),
			})
			return nil
		}

		// Skip ignored paths
		if w.ignorePaths[path] {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Calculate checksum
		data, err := os.ReadFile(path)
		if err != nil {
			events = append(events, Event{
				Type:      EventPermError,
				Path:      path,
				Timestamp: time.Now().UTC(),
				Error:     err.Error(),
			})
			return nil
		}

		checksum := w.calculateChecksum(data)

		// Check if file is new or modified
		oldChecksum, exists := w.checksums[path]
		if !exists {
			// New file
			events = append(events, Event{
				Type:      EventCreated,
				Path:      path,
				Timestamp: time.Now().UTC(),
				Checksum:  checksum,
				Size:      info.Size(),
			})
			w.checksums[path] = checksum
		} else if oldChecksum != checksum {
			// Modified file
			events = append(events, Event{
				Type:        EventModified,
				Path:        path,
				Timestamp:   time.Now().UTC(),
				Checksum:    checksum,
				OldChecksum: oldChecksum,
				Size:        info.Size(),
			})
			w.checksums[path] = checksum
		}

		return nil
	})

	// Check for deleted files
	for path := range w.checksums {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			events = append(events, Event{
				Type:      EventDeleted,
				Path:      path,
				Timestamp: time.Now().UTC(),
			})
			delete(w.checksums, path)
		}
	}

	return events, err
}

// GetCurrentChecksums returns a copy of current checksums
func (w *Watcher) GetCurrentChecksums() map[string]string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	checksums := make(map[string]string)
	for k, v := range w.checksums {
		checksums[k] = v
	}
	return checksums
}

// IgnorePath adds a path to ignore
func (w *Watcher) IgnorePath(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ignorePaths[path] = true
}

// UnignorePath removes a path from ignore list
func (w *Watcher) UnignorePath(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.ignorePaths, path)
}

// ForceChecksum forces a checksum for a path
func (w *Watcher) ForceChecksum(path string, checksum string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checksums[path] = checksum
}

// ExportChecksums exports checksums to JSON
func (w *Watcher) ExportChecksums() (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	data, err := json.MarshalIndent(w.checksums, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ImportChecksums imports checksums from JSON
func (w *Watcher) ImportChecksums(jsonData string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var checksums map[string]string
	if err := json.Unmarshal([]byte(jsonData), &checksums); err != nil {
		return err
	}

	w.checksums = checksums
	return nil
}

// Verify verifies all files match their checksums
func (w *Watcher) Verify() (map[string]bool, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	results := make(map[string]bool)

	for path, expectedChecksum := range w.checksums {
		data, err := os.ReadFile(path)
		if err != nil {
			results[path] = false
			continue
		}

		actualChecksum := w.calculateChecksum(data)
		results[path] = (actualChecksum == expectedChecksum)
	}

	return results, nil
}

// Private methods

func (w *Watcher) watchLoop() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			events, err := w.Scan()
			if err != nil {
				continue
			}

			w.mu.RLock()
			handlers := make([]Handler, len(w.handlers))
			copy(handlers, w.handlers)
			w.mu.RUnlock()

			for _, event := range events {
				for _, handler := range handlers {
					handler(event)
				}
			}
		}
	}
}

func (w *Watcher) initializeChecksums() error {
	return filepath.Walk(w.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if w.ignorePaths[path] {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		w.checksums[path] = w.calculateChecksum(data)
		return nil
	})
}

func (w *Watcher) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// UnauthorizedChangeReporter reports unauthorized changes
type UnauthorizedChangeReporter struct {
	Events    []Event   `json:"events"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
}

// NewUnauthorizedChangeReporter creates a reporter for unauthorized changes
func NewUnauthorizedChangeReporter(events []Event, severity string) *UnauthorizedChangeReporter {
	return &UnauthorizedChangeReporter{
		Events:    events,
		Timestamp: time.Now().UTC(),
		Severity:  severity,
	}
}

// ToJSON converts the report to JSON
func (r *UnauthorizedChangeReporter) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Summary returns a summary of the changes
func (r *UnauthorizedChangeReporter) Summary() string {
	modified := 0
	created := 0
	deleted := 0

	for _, event := range r.Events {
		switch event.Type {
		case EventModified:
			modified++
		case EventCreated:
			created++
		case EventDeleted:
			deleted++
		}
	}

	return fmt.Sprintf("Unauthorized changes detected: %d modified, %d created, %d deleted", modified, created, deleted)
}
