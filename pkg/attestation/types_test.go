// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Attestation Type Registry tests (v3.5.0+, Tier 5 prep)
//
// types_test.go covers the type registry, subject grammar
// (URI-style), and kind registration.

package attestation

import (
	"testing"
)

// --------------------------------------------------------------------
// ValidateType
// --------------------------------------------------------------------

func TestValidateType_AllRegistered(t *testing.T) {
	t.Parallel()
	for _, ty := range RegisteredTypes() {
		if err := ValidateType(ty); err != nil {
			t.Errorf("ValidateType(%q) returned error: %v", ty, err)
		}
	}
}

func TestValidateType_Unknown(t *testing.T) {
	t.Parallel()
	err := ValidateType("nonexistent.type.v99")
	if err == nil {
		t.Error("expected error on unknown type, got nil")
	}
}

func TestValidateType_Empty(t *testing.T) {
	t.Parallel()
	err := ValidateType("")
	if err == nil {
		t.Error("expected error on empty type, got nil")
	}
}

// --------------------------------------------------------------------
// RegisterType
// --------------------------------------------------------------------

func TestRegisterType_HappyPath(t *testing.T) {
	// Don't use t.Parallel() because this test mutates the
	// global allTypes map.
	// Use a unique type to avoid colliding with other tests.
	custom := Type("test.custom.v1")
	// Clean up: remove from the registry at the end.
	defer delete(allTypes, custom)

	err := RegisterType(custom, TypeSpec{
		Domain: "test", Name: "custom", Version: 1,
		Owner: "test-package",
	})
	if err != nil {
		t.Fatalf("RegisterType: %v", err)
	}
	// Verify the new type is now valid.
	if err := ValidateType(custom); err != nil {
		t.Errorf("newly registered type should validate: %v", err)
	}
}

func TestRegisterType_Duplicate(t *testing.T) {
	// TypeEvidenceManifest is already registered.
	err := RegisterType(TypeEvidenceManifest, TypeSpec{
		Domain: "evidence", Name: "manifest", Version: 2,
		Owner: "test",
	})
	if err == nil {
		t.Error("expected error on duplicate registration, got nil")
	}
}

func TestRegisterType_MissingFields(t *testing.T) {
	// Missing Domain.
	custom := Type("test.missing.v1")
	defer delete(allTypes, custom)
	err := RegisterType(custom, TypeSpec{
		Name: "missing", Version: 1, Owner: "test",
	})
	if err == nil {
		t.Error("expected error on missing Domain, got nil")
	}
	// Missing Owner.
	custom2 := Type("test.missing2.v1")
	defer delete(allTypes, custom2)
	err = RegisterType(custom2, TypeSpec{
		Domain: "test", Name: "missing2", Version: 1,
	})
	if err == nil {
		t.Error("expected error on missing Owner, got nil")
	}
}

// --------------------------------------------------------------------
// parseSubject (URI-style grammar)
// --------------------------------------------------------------------

func TestParseSubject_HappyPath(t *testing.T) {
	t.Parallel()
	kind, id, err := parseSubject("aegisgate://prompt/sha256-abc123")
	if err != nil {
		t.Fatal(err)
	}
	if kind != "prompt" {
		t.Errorf("kind = %q, want prompt", kind)
	}
	if id != "sha256-abc123" {
		t.Errorf("id = %q, want sha256-abc123", id)
	}
}

func TestParseSubject_IDWithSlashes(t *testing.T) {
	// Per the URI grammar, the id can contain slashes (it's
	// everything after the kind). The parseSubject function
	// splits on the FIRST slash, so the rest is the id.
	t.Parallel()
	kind, id, err := parseSubject("aegisgate://cve/CVE-2026-12345/details")
	if err != nil {
		t.Fatal(err)
	}
	if kind != "cve" {
		t.Errorf("kind = %q, want cve", kind)
	}
	if id != "CVE-2026-12345/details" {
		t.Errorf("id = %q, want CVE-2026-12345/details", id)
	}
}

func TestParseSubject_WrongScheme(t *testing.T) {
	t.Parallel()
	_, _, err := parseSubject("https://prompt/sha256-abc")
	if err == nil {
		t.Error("expected error on wrong scheme, got nil")
	}
}

func TestParseSubject_EmptySubject(t *testing.T) {
	t.Parallel()
	_, _, err := parseSubject("")
	if err == nil {
		t.Error("expected error on empty subject, got nil")
	}
}

func TestParseSubject_NoPath(t *testing.T) {
	t.Parallel()
	_, _, err := parseSubject("aegisgate://")
	if err == nil {
		t.Error("expected error on subject with no path, got nil")
	}
}

func TestParseSubject_OnlyKind(t *testing.T) {
	t.Parallel()
	_, _, err := parseSubject("aegisgate://prompt")
	if err == nil {
		t.Error("expected error on subject with no id, got nil")
	}
}

func TestParseSubject_EmptyID(t *testing.T) {
	t.Parallel()
	_, _, err := parseSubject("aegisgate://prompt/")
	if err == nil {
		t.Error("expected error on subject with empty id, got nil")
	}
}

func TestParseSubject_EmptyKind(t *testing.T) {
	t.Parallel()
	_, _, err := parseSubject("aegisgate:///something")
	if err == nil {
		t.Error("expected error on subject with empty kind, got nil")
	}
}

func TestParseSubject_NonASCII(t *testing.T) {
	t.Parallel()
	_, _, err := parseSubject("aegisgate://prompt/\u00e9clair")
	if err == nil {
		t.Error("expected error on non-ASCII id, got nil")
	}
}

// --------------------------------------------------------------------
// validateSubject (high-level)
// --------------------------------------------------------------------

func TestValidateSubject_HappyPath(t *testing.T) {
	t.Parallel()
	kind, id, err := validateSubject("aegisgate://manifest/550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatal(err)
	}
	if kind != "manifest" || id != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("got kind=%q id=%q", kind, id)
	}
}

func TestValidateSubject_UnknownKind(t *testing.T) {
	t.Parallel()
	_, _, err := validateSubject("aegisgate://unknown-kind/some-id")
	if err == nil {
		t.Error("expected error on unknown kind, got nil")
	}
}

// --------------------------------------------------------------------
// RegisterKind
// --------------------------------------------------------------------

func TestRegisterKind_HappyPath(t *testing.T) {
	// Don't use t.Parallel() because this test mutates the
	// global knownKinds map.
	kind := "test-kind-xyz"
	defer delete(knownKinds, kind)

	if err := RegisterKind(kind); err != nil {
		t.Fatal(err)
	}
	if !knownKinds[kind] {
		t.Errorf("kind %q not registered", kind)
	}
}

func TestRegisterKind_Empty(t *testing.T) {
	t.Parallel()
	if err := RegisterKind(""); err == nil {
		t.Error("expected error on empty kind, got nil")
	}
}

func TestRegisterKind_NonASCII(t *testing.T) {
	t.Parallel()
	if err := RegisterKind("\u00e9"); err == nil {
		t.Error("expected error on non-ASCII kind, got nil")
	}
}

func TestRegisterKind_Duplicate(t *testing.T) {
	// "prompt" is already registered.
	t.Parallel()
	if err := RegisterKind("prompt"); err == nil {
		t.Error("expected error on duplicate kind, got nil")
	}
}

// --------------------------------------------------------------------
// RegisteredTypes / RegisteredKinds (diagnostic helpers)
// --------------------------------------------------------------------

func TestRegisteredTypes_Sorted(t *testing.T) {
	t.Parallel()
	types := RegisteredTypes()
	// We expect at least 7 types (the initial set).
	if len(types) < 7 {
		t.Errorf("got %d types, want at least 7", len(types))
	}
	// Verify sorted.
	for i := 1; i < len(types); i++ {
		if types[i-1] > types[i] {
			t.Errorf("not sorted: %q > %q", types[i-1], types[i])
			break
		}
	}
}

func TestRegisteredKinds_Sorted(t *testing.T) {
	t.Parallel()
	kinds := RegisteredKinds()
	// We expect at least 8 kinds.
	if len(kinds) < 8 {
		t.Errorf("got %d kinds, want at least 8", len(kinds))
	}
	// Verify sorted.
	for i := 1; i < len(kinds); i++ {
		if kinds[i-1] > kinds[i] {
			t.Errorf("not sorted: %q > %q", kinds[i-1], kinds[i])
			break
		}
	}
}
