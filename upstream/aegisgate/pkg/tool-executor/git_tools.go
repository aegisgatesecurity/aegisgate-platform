// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// Git tools for status, log, and diff operations.
// =========================================================================

package toolexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// GIT STATUS EXECUTOR
// ============================================================================

// GitStatusExecutor handles git status operations
type GitStatusExecutor struct {
	allowedPaths []string
	blockedPaths []string
}

// NewGitStatusExecutor creates a new git status executor
func NewGitStatusExecutor(allowedPaths, blockedPaths []string) *GitStatusExecutor {
	return &GitStatusExecutor{
		allowedPaths: allowedPaths,
		blockedPaths: blockedPaths,
	}
}

// Name returns the tool name
func (e *GitStatusExecutor) Name() string {
	return "git_status"
}

// Execute returns git repository status
func (e *GitStatusExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	// Get optional path parameter
	repoPath := "."
	if path, ok := params["path"].(string); ok && path != "" {
		repoPath = path
	}

	// Validate path
	if err := e.validatePath(repoPath); err != nil {
		return nil, err
	}

	// Get porcelain status
	cmd := exec.Command("git", "-C", repoPath, "status", "--porcelain")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("git status timeout")
	case err := <-done:
		if err != nil {
			return nil, errors.New("git status failed: " + stderr.String())
		}

		return parseGitStatus(stdout.String(), repoPath), nil
	}
}

// Validate checks parameters
func (e *GitStatusExecutor) Validate(params map[string]interface{}) error {
	path, ok := params["path"].(string)
	if ok && path != "" {
		return e.validatePath(path)
	}
	return nil
}

// Timeout returns the execution timeout
func (e *GitStatusExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *GitStatusExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *GitStatusExecutor) Description() string {
	return "Get git repository status (porcelain format)"
}

func (e *GitStatusExecutor) validatePath(path string) error {
	// Check blocked paths
	for _, blocked := range e.blockedPaths {
		if strings.HasPrefix(path, blocked) {
			return errors.New("path is in blocked list: " + path)
		}
	}

	// If allowed list is set, check it
	if len(e.allowedPaths) > 0 {
		allowed := false
		for _, allowedPath := range e.allowedPaths {
			if strings.HasPrefix(path, allowedPath) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("path is not in allowed list")
		}
	}

	return nil
}

func parseGitStatus(output, repoPath string) map[string]interface{} {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	status := map[string]interface{}{
		"repo_path": repoPath,
		"is_clean":  true,
		"files":     []map[string]interface{}{},
	}

	var staged, modified, untracked []map[string]interface{}

	for _, line := range lines {
		if len(line) < 3 {
			continue
		}

		indexStatus := string(line[0])
		workTreeStatus := string(line[1])
		filePath := strings.TrimSpace(line[3:])

		fileInfo := map[string]interface{}{
			"path":     filePath,
			"index":    indexStatus,
			"worktree": workTreeStatus,
		}

		// Categorize by status
		if indexStatus == "?" && workTreeStatus == "?" {
			untracked = append(untracked, fileInfo)
			status["is_clean"] = false
		} else if indexStatus != " " && indexStatus != "?" {
			staged = append(staged, fileInfo)
			status["is_clean"] = false
		}

		if workTreeStatus != " " && workTreeStatus != "?" {
			modified = append(modified, fileInfo)
			status["is_clean"] = false
		}
	}

	status["staged"] = staged
	status["modified"] = modified
	status["untracked"] = untracked
	status["staged_count"] = len(staged)
	status["modified_count"] = len(modified)
	status["untracked_count"] = len(untracked)

	return status
}

// ============================================================================
// GIT LOG EXECUTOR
// ============================================================================

// GitLogExecutor handles git log operations
type GitLogExecutor struct {
	maxCommits int
	allowedPaths []string
	blockedPaths []string
}

// NewGitLogExecutor creates a new git log executor
func NewGitLogExecutor(maxCommits int, allowedPaths, blockedPaths []string) *GitLogExecutor {
	if maxCommits <= 0 {
		maxCommits = 50
	}
	if maxCommits > 100 {
		maxCommits = 100
	}
	return &GitLogExecutor{
		maxCommits:  maxCommits,
		allowedPaths: allowedPaths,
		blockedPaths: blockedPaths,
	}
}

// Name returns the tool name
func (e *GitLogExecutor) Name() string {
	return "git_log"
}

// Execute returns git log entries
func (e *GitLogExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	repoPath := "."
	if path, ok := params["path"].(string); ok && path != "" {
		repoPath = path
	}

	// Validate path
	if err := e.validateLogPath(repoPath); err != nil {
		return nil, err
	}

	// Get limit from params
	limit := e.maxCommits
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
		if limit <= 0 {
			limit = 10
		}
		if limit > 100 {
			limit = 100
		}
	}

	// Get optional branch/revision filter
	branch := ""
	if b, ok := params["branch"].(string); ok && b != "" {
		branch = b
	}

	// Build git log command with JSON output
	args := []string{"-C", repoPath, "log"}
	if branch != "" {
		args = append(args, branch)
	}
	args = append(args, "--format={\"hash\":\"%H\",\"shortHash\":\"%h\",\"author\":\"%an\",\"email\":\"%ae\",\"date\":\"%aI\",\"subject\":\"%s\",\"body\":\"%b\"}", "-n", strconv.Itoa(limit))

	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("git log timeout")
	case err := <-done:
		if err != nil {
			return nil, errors.New("git log failed: " + stderr.String())
		}

		return parseGitLog(stdout.String(), repoPath, limit), nil
	}
}

// Validate checks parameters
func (e *GitLogExecutor) Validate(params map[string]interface{}) error {
	path, ok := params["path"].(string)
	if ok && path != "" {
		return e.validateLogPath(path)
	}
	return nil
}

// Timeout returns the execution timeout
func (e *GitLogExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *GitLogExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *GitLogExecutor) Description() string {
	return "Get git commit log (JSON format)"
}

func (e *GitLogExecutor) validateLogPath(path string) error {
	for _, blocked := range e.blockedPaths {
		if strings.HasPrefix(path, blocked) {
			return errors.New("path is in blocked list: " + path)
		}
	}

	if len(e.allowedPaths) > 0 {
		allowed := false
		for _, allowedPath := range e.allowedPaths {
			if strings.HasPrefix(path, allowedPath) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("path is not in allowed list")
		}
	}

	return nil
}

func parseGitLog(output, repoPath string, limit int) map[string]interface{} {
	var commits []map[string]interface{}
	
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "{}" {
			continue
		}

		// Fix potential JSON issues
		line = strings.ReplaceAll(line, "\n", " ")
		line = strings.ReplaceAll(line, "\r", "")

		var commit map[string]interface{}
		if err := json.Unmarshal([]byte(line), &commit); err == nil {
			commits = append(commits, commit)
		}
	}

	return map[string]interface{}{
		"repo_path":  repoPath,
		"count":      len(commits),
		"limit":      limit,
		"commits":    commits,
	}
}

// ============================================================================
// GIT DIFF EXECUTOR
// ============================================================================

// GitDiffExecutor handles git diff operations
type GitDiffExecutor struct {
	allowedPaths []string
	blockedPaths []string
}

// NewGitDiffExecutor creates a new git diff executor
func NewGitDiffExecutor(allowedPaths, blockedPaths []string) *GitDiffExecutor {
	return &GitDiffExecutor{
		allowedPaths: allowedPaths,
		blockedPaths: blockedPaths,
	}
}

// Name returns the tool name
func (e *GitDiffExecutor) Name() string {
	return "git_diff"
}

// Execute returns git diff information
func (e *GitDiffExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	repoPath := "."
	if path, ok := params["path"].(string); ok && path != "" {
		repoPath = path
	}

	// Validate path
	if err := e.validateDiffPath(repoPath); err != nil {
		return nil, err
	}

	// Determine diff scope
	staged := false
	if s, ok := params["staged"].(bool); ok && s {
		staged = true
	}

	// Optional file filter
	file := ""
	if f, ok := params["file"].(string); ok && f != "" {
		file = f
	}

	// Get diff stats first
	statsArgs := []string{"-C", repoPath, "diff", "--stat"}
	if staged {
		statsArgs = []string{"-C", repoPath, "diff", "--staged", "--stat"}
	}
	if file != "" {
		statsArgs = append(statsArgs, "--", file)
	}

	cmd := exec.Command("git", statsArgs...)
	var statsOut bytes.Buffer
	cmd.Stdout = &statsOut
	cmd.Run()

	// Get full diff
	diffArgs := []string{"-C", repoPath, "diff"}
	if staged {
		diffArgs = []string{"-C", repoPath, "diff", "--staged"}
	}
	if file != "" {
		diffArgs = append(diffArgs, "--", file)
	}

	cmd = exec.Command("git", diffArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, errors.New("git diff timeout")
	case err := <-done:
		if err != nil {
			return nil, errors.New("git diff failed: " + stderr.String())
		}

		return parseGitDiff(stdout.String(), statsOut.String(), repoPath, staged), nil
	}
}

// Validate checks parameters
func (e *GitDiffExecutor) Validate(params map[string]interface{}) error {
	path, ok := params["path"].(string)
	if ok && path != "" {
		return e.validateDiffPath(path)
	}
	return nil
}

// Timeout returns the execution timeout
func (e *GitDiffExecutor) Timeout() time.Duration {
	return 60 * time.Second
}

// RiskLevel returns the risk level
func (e *GitDiffExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *GitDiffExecutor) Description() string {
	return "Get git diff of changes"
}

func (e *GitDiffExecutor) validateDiffPath(path string) error {
	for _, blocked := range e.blockedPaths {
		if strings.HasPrefix(path, blocked) {
			return errors.New("path is in blocked list: " + path)
		}
	}

	if len(e.allowedPaths) > 0 {
		allowed := false
		for _, allowedPath := range e.allowedPaths {
			if strings.HasPrefix(path, allowedPath) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("path is not in allowed list")
		}
	}

	return nil
}

func parseGitDiff(diff, stats, repoPath string, staged bool) map[string]interface{} {
	result := map[string]interface{}{
		"repo_path": repoPath,
		"staged":    staged,
		"has_diff":  len(diff) > 0,
	}

	// Parse stats
	statsLines := strings.Split(strings.TrimSpace(stats), "\n")
	var filesChanged []map[string]interface{}
	totalAdditions, totalDeletions := 0, 0

	for _, line := range statsLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "changed") || strings.Contains(line, "insertion") {
			continue
		}

		// Parse stat line: " file | 2 ++"
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}

		fileName := strings.TrimSpace(parts[0])
		statPart := strings.TrimSpace(parts[1])

		// Extract numbers from stat
		var additions, deletions int
		statParts := strings.Fields(statPart)
		for i, sp := range statParts {
			if strings.Contains(sp, "+") {
				if i > 0 {
					num, _ := strconv.Atoi(statParts[i-1])
					additions = num
				}
			}
			if strings.Contains(sp, "-") {
				if i > 0 {
					num, _ := strconv.Atoi(statParts[i-1])
					deletions = num
				}
			}
		}

		if additions > 0 || deletions > 0 {
			filesChanged = append(filesChanged, map[string]interface{}{
				"file":      fileName,
				"additions": additions,
				"deletions": deletions,
			})
			totalAdditions += additions
			totalDeletions += deletions
		}
	}

	result["files"] = filesChanged
	result["files_count"] = len(filesChanged)
	result["additions"] = totalAdditions
	result["deletions"] = totalDeletions

	// Include first portion of diff (to avoid huge outputs)
	if len(diff) > 0 {
		maxDiffLen := 5000
		if len(diff) > maxDiffLen {
			result["diff_preview"] = diff[:maxDiffLen] + "\n... (truncated, " + strconv.Itoa(len(diff)-maxDiffLen) + " more characters)"
			result["diff_truncated"] = true
		} else {
			result["diff"] = diff
		}
	}

	return result
}
