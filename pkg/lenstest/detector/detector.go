// SPDX-License-Identifier: Apache-2.0
// Detector wrapper: spawns Node.js to run the JS Lens detector.
//
// Usage:
//
//	res, err := lenstest.Detect(ctx, "some prompt")
//	if err != nil { ... }
//	for _, d := range res.Detections { ... }
//
// This is the canonical way to exercise the production detector
// from Go tests. The same code path runs in the browser via the
// content script (manifest.json content_scripts.js array).
//
// Notes:
//   - One Node subprocess per Detect() call. Slower than in-process,
//     but 100% identical to the browser code path.
//   - Use DetectBatch() to amortize subprocess startup cost.
package detector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DefaultDetectScript is the Node.js wrapper that loads the Lens
// detector modules and runs detect() per input.
const DefaultDetectScript = "/tmp/detect.js"

// DefaultDistRoot is the path to the built Lens extension.
const DefaultDistRoot = "/tmp/lens-FINAL28"

// Detection mirrors the JSON shape produced by /tmp/detect.js.
type Detection struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Name     string `json:"name"`
	Match    string `json:"match"`
	Index    int    `json:"index"`
	Length   int    `json:"length"`
}

// DetectResult is the response from /tmp/detect.js for one input.
type DetectResult struct {
	Index      int         `json:"i"`
	Detections []Detection `json:"detections"`
	MS         float64     `json:"ms"`
	Error      string      `json:"error,omitempty"`
}

// Detector wraps a Node.js subprocess for running the JS detector.
//
// Not safe for concurrent use; create one per goroutine if needed.
type Detector struct {
	Script   string        // path to /tmp/detect.js
	DistRoot string        // path to /tmp/lens-FINAL28
	NodePath string        // path to node binary (default: "node")
	Timeout  time.Duration // per-call timeout (default: 30s)
}

// NewDetector returns a Detector with defaults.
func NewDetector() *Detector {
	return &Detector{
		Script:   DefaultDetectScript,
		DistRoot: DefaultDistRoot,
		NodePath: "node",
		Timeout:  30 * time.Second,
	}
}

// Detect runs detect() on a single prompt. Returns the parsed result.
// Errors include subprocess failures and timeouts.
func (d *Detector) Detect(ctx context.Context, prompt string) (*DetectResult, error) {
	results, err := d.DetectBatch(ctx, []string{prompt})
	if err != nil {
		return nil, err
	}
	if len(results) != 1 {
		return nil, fmt.Errorf("expected 1 result, got %d", len(results))
	}
	return &results[0], nil
}

// DetectBatch runs detect() on each prompt in a single subprocess.
// Faster than calling Detect() in a loop (amortizes Node startup).
//
// Output: one DetectResult per input, in input order. Errors from
// the subprocess are returned as Go errors; per-prompt errors are
// stored in the DetectResult.Error field.
func (d *Detector) DetectBatch(ctx context.Context, prompts []string) ([]DetectResult, error) {
	if len(prompts) == 0 {
		return nil, nil
	}

	// Build JSON array input
	inputJSON, err := json.Marshal(prompts)
	if err != nil {
		return nil, fmt.Errorf("lenstest: marshal prompts: %w", err)
	}

	// Build command
	cmd := exec.CommandContext(ctx, d.NodePath, d.Script)
	cmd.Env = append(os.Environ(),
		"LENS_DIST_ROOT="+d.DistRoot,
	)
	cmd.Stderr = os.Stderr // surface Node errors to test output

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("lenstest: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("lenstest: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("lenstest: start node: %w", err)
	}

	// Feed input
	go func() {
		defer stdin.Close()
		_, _ = io.WriteString(stdin, string(inputJSON))
	}()

	// Read JSON-line output
	var results []DetectResult
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024) // up to 16MB per line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r DetectResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("lenstest: parse output line: %w (line: %s)", err, line)
		}
		results = append(results, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("lenstest: read stdout: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("lenstest: node exited: %w", err)
	}

	if len(results) != len(prompts) {
		return nil, fmt.Errorf("lenstest: expected %d results, got %d", len(prompts), len(results))
	}
	return results, nil
}

// FindDetection returns the first detection matching the given name, or nil.
func (r *DetectResult) FindDetection(name string) *Detection {
	for i := range r.Detections {
		if r.Detections[i].Name == name {
			return &r.Detections[i]
		}
	}
	return nil
}

// FindByCategory returns the first detection matching the given category, or nil.
func (r *DetectResult) FindByCategory(category string) *Detection {
	for i := range r.Detections {
		if r.Detections[i].Category == category {
			return &r.Detections[i]
		}
	}
	return nil
}
