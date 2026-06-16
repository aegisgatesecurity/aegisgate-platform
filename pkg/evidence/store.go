// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.3.0+)
//
// store.go is the local on-disk storage for evidence packages.
// Each manifest is stored as one JSON object per line in an
// append-only file. This is intentionally simple: no SQLite,
// no PostgreSQL, no migrations. Just a flat file that the
// founder can grep, copy, and email to their auditor.
//
// v3.3.0+ Track 2.

package evidence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// DefaultDir is the default directory for evidence-package storage.
// Can be overridden via AEGISGATE_DATA_DIR or the Store.Path option.
const DefaultDir = "var/evidence"

// Store persists evidence manifests to a local JSONL file. The
// store is safe for concurrent use (a single mutex serializes
// all I/O).
type Store struct {
	mu   sync.Mutex
	path string // full path to the JSONL file
}

// NewStore returns a Store that writes to dir/evidence.jsonl.
// The directory is created if it does not exist. If dir is empty,
// DefaultDir is used.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		dir = DefaultDir
	}
	//nolint:gosec // G301: 0o750 is acceptable for the evidence store
	// directory; the parent dir may be world-readable but the evidence
	// files themselves are 0o600.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("evidence store: mkdir %s: %w", dir, err)
	}
	return &Store{path: filepath.Join(dir, "evidence.jsonl")}, nil
}

// Path returns the absolute path to the JSONL file. Useful for
// the founder who wants to copy it to their auditor.
func (s *Store) Path() string {
	return s.path
}

// Put appends a manifest to the store. The manifest is serialized
// as a single line of JSON (no embedded newlines), followed by
// a single \n. This is the standard JSONL format.
//
// Returns an error if the manifest cannot be serialized or the
// file cannot be written. On error, the store is unchanged.
func (s *Store) Put(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("evidence store: nil manifest")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("evidence store: marshal: %w", err)
	}
	// Open with O_APPEND so concurrent writers from a backup tool
	// do not clobber our writes. O_CREATE ensures the file exists.
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("evidence store: open: %w", err)
	}
	defer func() { _ = f.Close() }()
	w := bufio.NewWriter(f)
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("evidence store: write: %w", err)
	}
	if err := w.WriteByte('\n'); err != nil {
		return fmt.Errorf("evidence store: write newline: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("evidence store: flush: %w", err)
	}
	return nil
}

// Get returns the manifest with the given ID, or an error if not found.
//
// In v0.1 we read the whole file linearly. This is fine for the
// "dozen manifests per customer per year" workload. A future v0.2
// can add a sidecar index for O(1) lookup if needed.
func (s *Store) Get(id string) (*Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAllLocked()
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.ManifestID == id {
			return m, nil
		}
	}
	return nil, fmt.Errorf("evidence store: manifest %q not found", id)
}

// List returns all stored manifests, sorted by GeneratedAt ascending.
// Limit caps the number of returned manifests; 0 means no limit.
func (s *Store) List(limit int) ([]*Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAllLocked()
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].GeneratedAt.Before(all[j].GeneratedAt)
	})
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// readAllLocked reads the JSONL file and unmarshals every line.
// Caller MUST hold s.mu. Returns an empty slice if the file does
// not exist (first-run case).
func (s *Store) readAllLocked() ([]*Manifest, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("evidence store: read: %w", err)
	}
	var out []*Manifest
	// Scan line by line. We use json.Decoder rather than splitting
	// on \n and json.Unmarshal-ing each line, because json.Decoder
	// is tolerant of trailing whitespace and trailing newlines.
	dec := json.NewDecoder(newBytesReader(data))
	for dec.More() {
		var m Manifest
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("evidence store: decode: %w", err)
		}
		out = append(out, &m)
	}
	return out, nil
}

// bytesReader is a tiny helper that wraps a []byte in an io.Reader.
// Avoids importing bytes just for this one call.
type bytesReader struct {
	buf []byte
	pos int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{buf: b} }

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.buf) {
		return 0, errEOF
	}
	n := copy(p, r.buf[r.pos:])
	r.pos += n
	return n, nil
}

// errEOF is io.EOF in disguise to avoid importing io just for this.
var errEOF = fmt.Errorf("EOF")
