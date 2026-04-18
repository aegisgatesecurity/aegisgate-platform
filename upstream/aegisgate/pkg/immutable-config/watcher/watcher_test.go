package watcher

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewWatcher(t *testing.T) {
	watcher, err := NewWatcher(nil)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	if watcher == nil {
		t.Error("Expected watcher to be created")
	}
}

func TestNewWatcherWithOptions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{
		BasePath:    tmpDir,
		Interval:    1 * time.Second,
		IgnorePaths: []string{filepath.Join(tmpDir, "ignore")},
	}

	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	if watcher.interval != 1*time.Second {
		t.Errorf("Expected interval 1s, got %v", watcher.interval)
	}
}

func TestNewWatcherWithEmptyBasePath(t *testing.T) {
	opts := &WatcherOptions{
		BasePath: "",
		Interval: 1 * time.Second,
	}

	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher with empty base path: %v", err)
	}

	// Scan should work but return empty
	events, err := watcher.Scan()
	if err != nil {
		t.Errorf("Unexpected error on scan: %v", err)
	}

	if len(events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(events))
	}
}

func TestDefaultWatcherOptions(t *testing.T) {
	opts := DefaultWatcherOptions()

	if opts.Interval != 5*time.Second {
		t.Errorf("Expected default interval 5s, got %v", opts.Interval)
	}
}

func TestAddHandler(t *testing.T) {
	watcher, _ := NewWatcher(nil)

	handler := func(event Event) {
		// Handler function
	}

	watcher.AddHandler(handler)

	if len(watcher.handlers) != 1 {
		t.Errorf("Expected 1 handler, got %d", len(watcher.handlers))
	}
}

func TestScanCreatedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{BasePath: tmpDir}
	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Create a file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Scan should detect the new file
	events, err := watcher.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	var createdEvent *Event
	for i := range events {
		if events[i].Type == EventCreated {
			createdEvent = &events[i]
			break
		}
	}

	if createdEvent == nil {
		t.Error("Expected created event for new file")
	} else if createdEvent.Path != testFile {
		t.Errorf("Expected path %s, got %s", testFile, createdEvent.Path)
	}
}

func TestScanModifiedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{BasePath: tmpDir}
	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Create initial file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("initial content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Initial scan to register checksum
	watcher.Scan()

	// Modify the file
	if err := os.WriteFile(testFile, []byte("modified content"), 0644); err != nil {
		t.Fatalf("Failed to modify test file: %v", err)
	}

	// Scan should detect modification
	events, err := watcher.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	var modifiedEvent *Event
	for i := range events {
		if events[i].Type == EventModified {
			modifiedEvent = &events[i]
			break
		}
	}

	if modifiedEvent == nil {
		t.Error("Expected modified event")
	} else {
		if modifiedEvent.OldChecksum == "" {
			t.Error("Expected old checksum")
		}
		if modifiedEvent.Checksum == "" {
			t.Error("Expected new checksum")
		}
	}
}

func TestScanDeletedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{BasePath: tmpDir}
	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Create and register file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Initial scan
	watcher.Scan()

	// Delete the file
	os.Remove(testFile)

	// Scan should detect deletion
	events, err := watcher.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	var deletedEvent *Event
	for i := range events {
		if events[i].Type == EventDeleted {
			deletedEvent = &events[i]
			break
		}
	}

	if deletedEvent == nil {
		t.Error("Expected deleted event")
	} else if deletedEvent.Path != testFile {
		t.Errorf("Expected path %s, got %s", testFile, deletedEvent.Path)
	}
}

func TestStartStop(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{
		BasePath: tmpDir,
		Interval: 100 * time.Millisecond,
	}

	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Start
	if err := watcher.Start(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	if !watcher.IsRunning() {
		t.Error("Expected watcher to be running")
	}

	// Starting again should fail
	if err := watcher.Start(); err == nil {
		t.Error("Expected error when starting already running watcher")
	}

	time.Sleep(50 * time.Millisecond)

	// Stop
	if err := watcher.Stop(); err != nil {
		t.Fatalf("Failed to stop watcher: %v", err)
	}

	if watcher.IsRunning() {
		t.Error("Expected watcher to not be running")
	}

	// Stop again should be safe (no-op)
	if err := watcher.Stop(); err != nil {
		t.Errorf("Unexpected error on second stop: %v", err)
	}
}

func TestIgnorePath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{BasePath: tmpDir}
	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	ignoreFile := filepath.Join(tmpDir, "ignored.txt")
	watcher.IgnorePath(ignoreFile)

	// Create ignored file
	if err := os.WriteFile(ignoreFile, []byte("ignored"), 0644); err != nil {
		t.Fatalf("Failed to create ignored file: %v", err)
	}

	// Scan
	events, err := watcher.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not detect the ignored file
	for _, event := range events {
		if event.Path == ignoreFile {
			t.Error("Expected ignored file to not generate event")
		}
	}
}

func TestUnignorePath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{BasePath: tmpDir}
	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	testFile := filepath.Join(tmpDir, "test.txt")

	// Ignore then unignore
	watcher.IgnorePath(testFile)
	watcher.UnignorePath(testFile)

	// Create file
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Scan
	events, err := watcher.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect the file now
	var found bool
	for _, event := range events {
		if event.Path == testFile && event.Type == EventCreated {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected unignored file to generate event")
	}
}

func TestForceChecksum(t *testing.T) {
	watcher, _ := NewWatcher(nil)

	watcher.ForceChecksum("/test/path", "abc123")

	checksums := watcher.GetCurrentChecksums()
	if checksums["/test/path"] != "abc123" {
		t.Errorf("Expected checksum abc123, got %s", checksums["/test/path"])
	}
}

func TestGetCurrentChecksums(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{BasePath: tmpDir}
	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Create file
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("test"), 0644)

	// Scan to register checksum
	watcher.Scan()

	checksums := watcher.GetCurrentChecksums()
	if len(checksums) != 1 {
		t.Errorf("Expected 1 checksum, got %d", len(checksums))
	}
}

func TestExportImportChecksums(t *testing.T) {
	watcher, _ := NewWatcher(nil)

	watcher.ForceChecksum("/path1", "checksum1")
	watcher.ForceChecksum("/path2", "checksum2")

	// Export
	jsonStr, err := watcher.ExportChecksums()
	if err != nil {
		t.Fatalf("Failed to export checksums: %v", err)
	}

	if jsonStr == "" {
		t.Error("Expected non-empty JSON string")
	}

	// Create new watcher and import
	watcher2, _ := NewWatcher(nil)
	err = watcher2.ImportChecksums(jsonStr)
	if err != nil {
		t.Fatalf("Failed to import checksums: %v", err)
	}

	checksums := watcher2.GetCurrentChecksums()
	if checksums["/path1"] != "checksum1" {
		t.Errorf("Expected checksum1, got %s", checksums["/path1"])
	}
	if checksums["/path2"] != "checksum2" {
		t.Errorf("Expected checksum2, got %s", checksums["/path2"])
	}
}

func TestImportChecksumsInvalidJSON(t *testing.T) {
	watcher, _ := NewWatcher(nil)

	err := watcher.ImportChecksums("invalid json")
	if err == nil {
		t.Error("Expected error when importing invalid JSON")
	}
}

func TestVerify(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{BasePath: tmpDir}
	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Create file
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("test content"), 0644)

	// Scan to register checksum
	watcher.Scan()

	// Verify - should pass
	results, err := watcher.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !results[testFile] {
		t.Error("Expected file to pass verification")
	}

	// Modify file without updating checksum
	os.WriteFile(testFile, []byte("modified content"), 0644)

	// Verify - should fail
	results, err = watcher.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if results[testFile] {
		t.Error("Expected file to fail verification after modification")
	}
}

func TestVerifyMissingFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{BasePath: tmpDir}
	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Force checksum for non-existent file
	watcher.ForceChecksum(filepath.Join(tmpDir, "missing.txt"), "somechecksum")

	// Verify
	results, err := watcher.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Missing file should fail verification
	for path, passed := range results {
		t.Logf("Path %s: %v", path, passed)
	}
}

func TestEventTypeConstants(t *testing.T) {
	if EventCreated != "created" {
		t.Errorf("Expected EventCreated to be 'created', got %s", EventCreated)
	}
	if EventModified != "modified" {
		t.Errorf("Expected EventModified to be 'modified', got %s", EventModified)
	}
	if EventDeleted != "deleted" {
		t.Errorf("Expected EventDeleted to be 'deleted', got %s", EventDeleted)
	}
	if EventRenamed != "renamed" {
		t.Errorf("Expected EventRenamed to be 'renamed', got %s", EventRenamed)
	}
	if EventPermError != "perm_error" {
		t.Errorf("Expected EventPermError to be 'perm_error', got %s", EventPermError)
	}
}

func TestUnauthorizedChangeReporter(t *testing.T) {
	events := []Event{
		{Type: EventCreated, Path: "/new/file.txt"},
		{Type: EventModified, Path: "/changed/file.txt"},
		{Type: EventDeleted, Path: "/deleted/file.txt"},
	}

	reporter := NewUnauthorizedChangeReporter(events, "high")

	if reporter.Severity != "high" {
		t.Errorf("Expected severity high, got %s", reporter.Severity)
	}

	if len(reporter.Events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(reporter.Events))
	}
}

func TestUnauthorizedChangeReporterToJSON(t *testing.T) {
	events := []Event{
		{Type: EventCreated, Path: "/new/file.txt", Timestamp: time.Now()},
	}

	reporter := NewUnauthorizedChangeReporter(events, "critical")

	jsonStr, err := reporter.ToJSON()
	if err != nil {
		t.Fatalf("Failed to convert to JSON: %v", err)
	}

	if jsonStr == "" {
		t.Error("Expected non-empty JSON string")
	}
}

func TestUnauthorizedChangeReporterSummary(t *testing.T) {
	events := []Event{
		{Type: EventCreated, Path: "/new1.txt"},
		{Type: EventCreated, Path: "/new2.txt"},
		{Type: EventModified, Path: "/changed1.txt"},
		{Type: EventModified, Path: "/changed2.txt"},
		{Type: EventModified, Path: "/changed3.txt"},
		{Type: EventDeleted, Path: "/deleted.txt"},
	}

	reporter := NewUnauthorizedChangeReporter(events, "medium")
	summary := reporter.Summary()

	if summary == "" {
		t.Error("Expected non-empty summary")
	}

	// Summary should contain counts
	// Format: "Unauthorized changes detected: X modified, Y created, Z deleted"
}

func TestWatcherHandlersCalled(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	opts := &WatcherOptions{
		BasePath: tmpDir,
		Interval: 50 * time.Millisecond,
	}

	watcher, err := NewWatcher(opts)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	var mu sync.Mutex
	var receivedEvents []Event
	watcher.AddHandler(func(event Event) {
		mu.Lock()
		receivedEvents = append(receivedEvents, event)
		mu.Unlock()
	})

	// Perform initial scan to establish baseline (empty at this point)
	// This ensures the watcher has an initial state before we start monitoring
	_, _ = watcher.Scan()

	// Start watcher
	if err := watcher.Start(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	// Create a file - this will be detected as "created" on next scan
	testFile := filepath.Join(tmpDir, "trigger.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wait for at least one scan cycle (interval is 50ms, wait 150ms to be safe)
	time.Sleep(150 * time.Millisecond)

	// Stop watcher
	watcher.Stop()

	// Check if handler was called with created event
	mu.Lock()
	found := false
	for _, e := range receivedEvents {
		if e.Path == testFile && e.Type == EventCreated {
			found = true
			break
		}
	}
	mu.Unlock()

	if !found {
		t.Error("Expected handler to be called with created event")
	}
}
