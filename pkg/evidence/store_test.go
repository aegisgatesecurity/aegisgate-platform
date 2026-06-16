// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.3.0+)
//
// store_test.go covers the JSONL append-only store. Each test
// uses a fresh temp dir to avoid interfering with sibling tests.
//
// v3.3.0+ Track 2.

package evidence

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore_PutAndGet(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	m := &Manifest{
		ManifestID:     "test-1",
		Framework:      "hipaa",
		GeneratedAt:    time.Now().UTC(),
		BuilderVersion: "v3.3.0-test",
	}
	if err := s.Put(m); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get("test-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ManifestID != "test-1" {
		t.Errorf("ManifestID = %q, want test-1", got.ManifestID)
	}
	if got.Framework != "hipaa" {
		t.Errorf("Framework = %q, want hipaa", got.Framework)
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	_, err := s.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

func TestStore_List(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	for i := 0; i < 5; i++ {
		err := s.Put(&Manifest{
			ManifestID:     "test-" + string(rune('a'+i)),
			Framework:      "hipaa",
			GeneratedAt:    time.Now().UTC().Add(time.Duration(i) * time.Second),
			BuilderVersion: "v3.3.0-test",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 5 {
		t.Errorf("len = %d, want 5", len(all))
	}
	// List should be sorted by GeneratedAt ascending.
	for i := 1; i < len(all); i++ {
		if all[i].GeneratedAt.Before(all[i-1].GeneratedAt) {
			t.Errorf("not sorted at index %d", i)
		}
	}
}

func TestStore_List_Limit(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	for i := 0; i < 10; i++ {
		_ = s.Put(&Manifest{
			ManifestID:     "test-" + string(rune('a'+i)),
			GeneratedAt:    time.Now().UTC(),
			BuilderVersion: "v3.3.0-test",
		})
	}
	all, err := s.List(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("len = %d, want 3", len(all))
	}
}

func TestStore_Path(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	want := filepath.Join(dir, "evidence.jsonl")
	if s.Path() != want {
		t.Errorf("Path = %q, want %q", s.Path(), want)
	}
}

func TestStore_AppendAcrossOpens(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	_ = s.Put(&Manifest{ManifestID: "first", BuilderVersion: "v"})
	// "Reopen" by creating a new Store handle on the same dir.
	s2, _ := NewStore(dir)
	_ = s2.Put(&Manifest{ManifestID: "second", BuilderVersion: "v"})
	all, _ := s2.List(0)
	if len(all) != 2 {
		t.Errorf("len = %d, want 2", len(all))
	}
}

func TestNewStore_EmptyDir(t *testing.T) {
	// Passing empty dir should fall back to DefaultDir relative
	// to the current working directory. We do not assert the
	// exact path (it depends on the test runner), but we assert
	// that NewStore succeeds and the resulting Path is non-empty.
	s, err := NewStore("")
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if s.Path() == "" {
		t.Error("Path is empty")
	}
}
