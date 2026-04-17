// Package tool-executor - File tool implementations
package toolexecutor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileTools provides safe file operation tools
type FileTools struct {
	allowedDirs []string
	maxFileSize int64
}

// NewFileTools creates a new file tools executor
func NewFileTools(allowedDirs []string, maxFileSize int64) *FileTools {
	return &FileTools{
		allowedDirs: allowedDirs,
		maxFileSize: maxFileSize,
	}
}

// FileReadExecutor handles file read operations
type FileReadExecutor struct {
	tools *FileTools
}

// validatePath is a method on FileTools, not individual executors
func (e *FileReadExecutor) validatePath(path string) error {
	return e.tools.validatePath(path)
}

// NewFileReadExecutor creates a new file read executor
func NewFileReadExecutor(tools *FileTools) *FileReadExecutor {
	return &FileReadExecutor{tools: tools}
}

// Name returns the tool name
func (e *FileReadExecutor) Name() string {
	return "file_read"
}

// Execute reads a file
func (e *FileReadExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return nil, errors.New("path parameter required")
	}

	// Security: validate path
	if err := e.validatePath(path); err != nil {
		return nil, err
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Check size limit
	if int64(len(data)) > e.tools.maxFileSize {
		return nil, errors.New("file exceeds maximum size")
	}

	return map[string]interface{}{
		"path":      path,
		"content":   string(data),
		"size":      len(data),
		"truncated": int64(len(data)) > e.tools.maxFileSize,
	}, nil
}

// Validate checks parameters
func (e *FileReadExecutor) Validate(params map[string]interface{}) error {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return errors.New("path parameter required")
	}
	return e.validatePath(path)
}

// Timeout returns the execution timeout
func (e *FileReadExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *FileReadExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *FileReadExecutor) Description() string {
	return "Read contents of a file"
}

// validatePath ensures the path is within allowed directories
func (e *FileTools) validatePath(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return errors.New("invalid path")
	}

	// If no allowed dirs specified, allow all (not recommended for production)
	if len(e.allowedDirs) == 0 {
		return nil
	}

	for _, dir := range e.allowedDirs {
		absDir, _ := filepath.Abs(dir)
		if strings.HasPrefix(absPath, absDir) {
			return nil
		}
	}

	return errors.New("path not within allowed directories")
}

// FileWriteExecutor handles file write operations
type FileWriteExecutor struct {
	tools *FileTools
}

// validatePath delegates to FileTools
func (e *FileWriteExecutor) validatePath(path string) error {
	return e.tools.validatePath(path)
}

// NewFileWriteExecutor creates a new file write executor
func NewFileWriteExecutor(tools *FileTools) *FileWriteExecutor {
	return &FileWriteExecutor{tools: tools}
}

// Name returns the tool name
func (e *FileWriteExecutor) Name() string {
	return "file_write"
}

// Execute writes to a file
func (e *FileWriteExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return nil, errors.New("path parameter required")
	}

	content, ok := params["content"].(string)
	if !ok {
		return nil, errors.New("content parameter required")
	}

	// Security: validate path
	if err := e.tools.validatePath(path); err != nil {
		return nil, err
	}

	// Check size limit
	if int64(len(content)) > e.tools.maxFileSize {
		return nil, errors.New("content exceeds maximum size")
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, errors.New("failed to create directory")
	}

	// Write file
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"path": path,
		"size": len(content),
		"ok":   true,
	}, nil
}

// Validate checks parameters
func (e *FileWriteExecutor) Validate(params map[string]interface{}) error {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return errors.New("path parameter required")
	}
	if err := e.tools.validatePath(path); err != nil {
		return err
	}

	_, ok = params["content"].(string)
	if !ok {
		return errors.New("content parameter required")
	}
	return nil
}

// Timeout returns the execution timeout
func (e *FileWriteExecutor) Timeout() time.Duration {
	return 60 * time.Second
}

// RiskLevel returns the risk level
func (e *FileWriteExecutor) RiskLevel() int {
	return int(RiskMedium)
}

// Description returns a description
func (e *FileWriteExecutor) Description() string {
	return "Write content to a file"
}

// FileDeleteExecutor handles file delete operations
type FileDeleteExecutor struct {
	tools *FileTools
}

// validatePath delegates to FileTools
func (e *FileDeleteExecutor) validatePath(path string) error {
	return e.tools.validatePath(path)
}

// NewFileDeleteExecutor creates a new file delete executor
func NewFileDeleteExecutor(tools *FileTools) *FileDeleteExecutor {
	return &FileDeleteExecutor{tools: tools}
}

// Name returns the tool name
func (e *FileDeleteExecutor) Name() string {
	return "file_delete"
}

// Execute deletes a file
func (e *FileDeleteExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return nil, errors.New("path parameter required")
	}

	// Security: validate path
	if err := e.tools.validatePath(path); err != nil {
		return nil, err
	}

	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("file does not exist")
		}
		return nil, err
	}

	// Delete file
	if err := os.Remove(path); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"path": path,
		"ok":   true,
	}, nil
}

// Validate checks parameters
func (e *FileDeleteExecutor) Validate(params map[string]interface{}) error {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return errors.New("path parameter required")
	}
	return e.tools.validatePath(path)
}

// Timeout returns the execution timeout
func (e *FileDeleteExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *FileDeleteExecutor) RiskLevel() int {
	return int(RiskHigh)
}

// Description returns a description
func (e *FileDeleteExecutor) Description() string {
	return "Delete a file"
}

// FileExistsExecutor checks if a file exists
type FileExistsExecutor struct {
	tools *FileTools
}

// validatePath delegates to FileTools
func (e *FileExistsExecutor) validatePath(path string) error {
	return e.tools.validatePath(path)
}

// NewFileExistsExecutor creates a new file exists executor
func NewFileExistsExecutor(tools *FileTools) *FileExistsExecutor {
	return &FileExistsExecutor{tools: tools}
}

// Name returns the tool name
func (e *FileExistsExecutor) Name() string {
	return "file_exists"
}

// Execute checks if a file exists
func (e *FileExistsExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return nil, errors.New("path parameter required")
	}

	// Security: validate path
	if err := e.tools.validatePath(path); err != nil {
		return nil, err
	}

	_, err := os.Stat(path)
	exists := err == nil
	isDir := false
	size := int64(0)

	if exists {
		info, _ := os.Stat(path)
		isDir = info.IsDir()
		if !isDir {
			size = info.Size()
		}
	}

	return map[string]interface{}{
		"path":   path,
		"exists": exists,
		"is_dir": isDir,
		"size":   size,
	}, nil
}

// Validate checks parameters
func (e *FileExistsExecutor) Validate(params map[string]interface{}) error {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return errors.New("path parameter required")
	}
	return e.tools.validatePath(path)
}

// Timeout returns the execution timeout
func (e *FileExistsExecutor) Timeout() time.Duration {
	return 10 * time.Second
}

// RiskLevel returns the risk level
func (e *FileExistsExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *FileExistsExecutor) Description() string {
	return "Check if a file exists"
}
