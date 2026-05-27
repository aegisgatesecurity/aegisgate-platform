package computeruse

import (
	"strings"
	"testing"
)

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()

	if id1 == "" {
		t.Error("generateID should not return empty string")
	}
	if id1 == id2 {
		t.Error("generateID should return unique IDs")
	}

	// Check prefix
	if !strings.HasPrefix(id1, "cu_") {
		t.Errorf("Expected prefix 'cu_', got %s", id1)
	}
}

func TestGenerateIDMultiple(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID()
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestRandomString(t *testing.T) {
	s1 := randomString(16)
	s2 := randomString(16)

	if len(s1) != 16 {
		t.Errorf("Expected length 16, got %d", len(s1))
	}
	if s1 == s2 {
		t.Error("randomString should return different strings")
	}

	// Check it's alphanumeric
	for _, c := range s1 {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789", c) {
			t.Errorf("randomString contains invalid char: %c", c)
		}
	}
}

func TestRandomStringDifferentLengths(t *testing.T) {
	s8 := randomString(8)
	s16 := randomString(16)
	s32 := randomString(32)

	if len(s8) != 8 {
		t.Errorf("Expected length 8, got %d", len(s8))
	}
	if len(s16) != 16 {
		t.Errorf("Expected length 16, got %d", len(s16))
	}
	if len(s32) != 32 {
		t.Errorf("Expected length 32, got %d", len(s32))
	}
}

func TestRandomStringEmpty(t *testing.T) {
	s := randomString(0)
	if s != "" {
		t.Error("randomString(0) should return empty string")
	}
}
