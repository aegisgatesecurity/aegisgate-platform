// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Module webhook parsing tests (v3.2.0 Phase 1.3)
//
// Tests the 3 input shapes for module line items in Stripe checkout
// sessions: subscription_items.data[].price.lookup_key, metadata.modules
// (CSV), and the empty/legacy shape. Also tests the moduleFromLookupKey
// helper, the moduleLineItemAmount helper, and the AddModules interface
// contract on MockLicenseGenerator.

package webhook

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// ---- moduleFromLookupKey ----

func TestModuleFromLookupKey(t *testing.T) {
	cases := []struct {
		lookupKey string
		want      string
	}{
		// Module keys.
		{"module_hipaa", "hipaa"},
		{"module_pci", "pci"},
		{"module_soc2", "soc2"},
		{"module_iso42001", "iso42001"},
		{"module_fedramp", "fedramp"},
		{"module_fips", "fips"},
		// Non-module keys.
		{"professional", ""},
		{"starter_monthly", ""},
		{"", ""},
		{"module_", ""},
		// Edge: prefix only.
		{"MODULE_HIPAA", ""}, // case-sensitive
	}
	for _, tc := range cases {
		t.Run(tc.lookupKey, func(t *testing.T) {
			if got := moduleFromLookupKey(tc.lookupKey); got != tc.want {
				t.Errorf("moduleFromLookupKey(%q) = %q, want %q", tc.lookupKey, got, tc.want)
			}
		})
	}
}

// ---- parseModulesFromSession: shape 1 (subscription_items) ----

func TestParseModulesFromSession_SubscriptionItems_SingleModule(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		SubscriptionItems: SubscriptionItemsWrapper{
			Data: []SubscriptionItem{
				{ID: "si_1", Price: SubscriptionItemPrice{LookupKey: "module_hipaa", UnitAmount: 9900}},
			},
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	if len(modules) != 1 || modules[0] != "hipaa" {
		t.Errorf("got %v, want [hipaa]", modules)
	}
}

func TestParseModulesFromSession_SubscriptionItems_MultipleModules(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		SubscriptionItems: SubscriptionItemsWrapper{
			Data: []SubscriptionItem{
				{ID: "si_1", Price: SubscriptionItemPrice{LookupKey: "module_hipaa", UnitAmount: 9900}},
				{ID: "si_2", Price: SubscriptionItemPrice{LookupKey: "module_pci", UnitAmount: 9900}},
				{ID: "si_3", Price: SubscriptionItemPrice{LookupKey: "professional", UnitAmount: 24900}}, // not a module
			},
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	want := map[string]bool{"hipaa": true, "pci": true}
	if len(modules) != len(want) {
		t.Fatalf("got %v, want %v", modules, want)
	}
	for _, m := range modules {
		if !want[m] {
			t.Errorf("unexpected module: %s", m)
		}
	}
}

func TestParseModulesFromSession_SubscriptionItems_RejectsInvalid(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		SubscriptionItems: SubscriptionItemsWrapper{
			Data: []SubscriptionItem{
				{ID: "si_1", Price: SubscriptionItemPrice{LookupKey: "module_bogus"}},
			},
		},
	}
	_, err := s.parseModulesFromSession(session)
	if err == nil {
		t.Fatal("expected error for invalid module, got nil")
	}
	if !errors.Is(err, ErrInvalidModule) {
		t.Errorf("expected ErrInvalidModule, got %v", err)
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error should mention 'bogus', got %q", err.Error())
	}
}

func TestParseModulesFromSession_SubscriptionItems_Deduplicates(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		SubscriptionItems: SubscriptionItemsWrapper{
			Data: []SubscriptionItem{
				{ID: "si_1", Price: SubscriptionItemPrice{LookupKey: "module_hipaa"}},
				{ID: "si_2", Price: SubscriptionItemPrice{LookupKey: "module_hipaa"}}, // dup
				{ID: "si_3", Price: SubscriptionItemPrice{LookupKey: "module_hipaa"}}, // dup
			},
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	if len(modules) != 1 || modules[0] != "hipaa" {
		t.Errorf("got %v, want [hipaa] (deduplicated)", modules)
	}
}

// ---- parseModulesFromSession: shape 2 (metadata.modules CSV) ----

func TestParseModulesFromSession_MetadataCSV(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		Metadata: map[string]string{
			"modules": "hipaa,pci",
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	want := map[string]bool{"hipaa": true, "pci": true}
	if len(modules) != len(want) {
		t.Fatalf("got %v, want %v", modules, want)
	}
	for _, m := range modules {
		if !want[m] {
			t.Errorf("unexpected module: %s", m)
		}
	}
}

func TestParseModulesFromSession_MetadataCSV_HandlesWhitespace(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		Metadata: map[string]string{
			"modules": "  hipaa , pci  ,  soc2  ",
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	if len(modules) != 3 {
		t.Errorf("got %v, want 3 modules", modules)
	}
}

func TestParseModulesFromSession_MetadataCSV_RejectsInvalid(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		Metadata: map[string]string{
			"modules": "hipaa,bogus,pci",
		},
	}
	_, err := s.parseModulesFromSession(session)
	if err == nil {
		t.Fatal("expected error for invalid module in CSV, got nil")
	}
	if !errors.Is(err, ErrInvalidModule) {
		t.Errorf("expected ErrInvalidModule, got %v", err)
	}
}

func TestParseModulesFromSession_MetadataCSV_Empty(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		Metadata: map[string]string{
			"modules": "",
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	if len(modules) != 0 {
		t.Errorf("got %v, want empty", modules)
	}
}

// ---- parseModulesFromSession: shape 3 (legacy, no modules) ----

func TestParseModulesFromSession_LegacyNoModules(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		Metadata: map[string]string{
			"tier": "professional",
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	if len(modules) != 0 {
		t.Errorf("got %v, want empty (legacy single-tier)", modules)
	}
}

// ---- parseModulesFromSession: combined shapes (priority order) ----

func TestParseModulesFromSession_BothShapesPresent(t *testing.T) {
	// When BOTH subscription_items and metadata.modules are present,
	// both are merged (de-duplicated). No priority; this is the union
	// of both sources. This is intentional: Stripe may use both in
	// different flows (e.g., one-off CSV override + a recurring schedule).
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		SubscriptionItems: SubscriptionItemsWrapper{
			Data: []SubscriptionItem{
				{ID: "si_1", Price: SubscriptionItemPrice{LookupKey: "module_hipaa"}},
			},
		},
		Metadata: map[string]string{
			"modules": "pci,soc2",
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	if len(modules) != 3 {
		t.Errorf("got %v, want 3 (hipaa, pci, soc2)", modules)
	}
}

// ---- moduleLineItemAmount ----

func TestModuleLineItemAmount_Empty(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{}
	amount := s.moduleLineItemAmount(session, nil)
	if amount != 0 {
		t.Errorf("amount = %d, want 0", amount)
	}
}

func TestModuleLineItemAmount_SumsModuleItems(t *testing.T) {
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		SubscriptionItems: SubscriptionItemsWrapper{
			Data: []SubscriptionItem{
				{ID: "si_1", Price: SubscriptionItemPrice{LookupKey: "module_hipaa", UnitAmount: 9900}},
				{ID: "si_2", Price: SubscriptionItemPrice{LookupKey: "module_pci", UnitAmount: 9900}},
				{ID: "si_3", Price: SubscriptionItemPrice{LookupKey: "professional", UnitAmount: 24900}}, // not a module
			},
		},
	}
	amount := s.moduleLineItemAmount(session, []string{"hipaa", "pci"})
	if amount != 19800 { // 9900 + 9900
		t.Errorf("amount = %d, want 19800", amount)
	}
}

func TestModuleLineItemAmount_IgnoresNonModuleItems(t *testing.T) {
	// Modules list is empty -> should return 0 even if session has items.
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		SubscriptionItems: SubscriptionItemsWrapper{
			Data: []SubscriptionItem{
				{ID: "si_1", Price: SubscriptionItemPrice{LookupKey: "professional", UnitAmount: 24900}},
			},
		},
	}
	amount := s.moduleLineItemAmount(session, nil)
	if amount != 0 {
		t.Errorf("amount = %d, want 0 (no modules in modules list)", amount)
	}
}

// ---- handleCheckoutCompleted integration: full checkout with modules ----

func TestHandleCheckoutCompleted_WithModules(t *testing.T) {
	// Realistic Stripe payload: customer bought Professional + HIPAA.
	payload := map[string]any{
		"id":             "cs_test_1",
		"customer_email": "test@example.com",
		"customer":       "cus_test_1",
		"payment_status": "paid",
		"amount_total":   24900 + 9900,
		"currency":       "usd",
		"metadata":       map[string]string{"tier": "professional"},
		"subscription_items": map[string]any{
			"data": []map[string]any{
				{"id": "si_1", "price": map[string]any{
					"id":          "price_pro_monthly",
					"lookup_key":  "professional",
					"unit_amount": 24900,
				}},
				{"id": "si_2", "price": map[string]any{
					"id":          "price_module_hipaa",
					"lookup_key":  "module_hipaa",
					"unit_amount": 9900,
				}},
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	mockGen := NewMockLicenseGenerator()
	s := &Server{
		logger:       discardLogger(),
		licenseGen:   mockGen,
		emailService: NewMockEmailService(),
	}
	if err := s.handleCheckoutCompleted(data); err != nil {
		t.Fatalf("handleCheckoutCompleted: %v", err)
	}

	// Verify the mock got both a license generated AND a module attached.
	// The mock records the license key but doesn't record modules (it's a
	// mock). What we CAN verify: no error was returned, which means the
	// AddModules call succeeded (the mock's no-op implementation returned nil).
}

func TestHandleCheckoutCompleted_WithModulesViaMetadata(t *testing.T) {
	// Modules come via metadata.modules CSV (the legacy/manual shape).
	payload := map[string]any{
		"id":             "cs_test_2",
		"customer_email": "test@example.com",
		"customer":       "cus_test_2",
		"payment_status": "paid",
		"amount_total":   7900,
		"currency":       "usd",
		"metadata": map[string]string{
			"tier":    "developer",
			"modules": "hipaa,pci",
		},
	}
	data, _ := json.Marshal(payload)

	s := &Server{
		logger:       discardLogger(),
		licenseGen:   NewMockLicenseGenerator(),
		emailService: NewMockEmailService(),
	}
	if err := s.handleCheckoutCompleted(data); err != nil {
		t.Fatalf("handleCheckoutCompleted: %v", err)
	}
}

func TestHandleCheckoutCompleted_RejectsInvalidModuleInSubscriptionItems(t *testing.T) {
	// A "module_bogus" lookup_key is a typo and should be rejected.
	payload := map[string]any{
		"id":             "cs_test_3",
		"customer_email": "test@example.com",
		"customer":       "cus_test_3",
		"payment_status": "paid",
		"amount_total":   9900,
		"metadata":       map[string]string{"tier": "developer"},
		"subscription_items": map[string]any{
			"data": []map[string]any{
				{"id": "si_1", "price": map[string]any{
					"lookup_key":  "module_bogus",
					"unit_amount": 9900,
				}},
			},
		},
	}
	data, _ := json.Marshal(payload)

	s := &Server{
		logger:       discardLogger(),
		licenseGen:   NewMockLicenseGenerator(),
		emailService: NewMockEmailService(),
	}
	err := s.handleCheckoutCompleted(data)
	if err == nil {
		t.Fatal("expected error for invalid module, got nil")
	}
	if !errors.Is(err, ErrInvalidModule) {
		t.Errorf("expected ErrInvalidModule, got %v", err)
	}
}

func TestHandleCheckoutCompleted_RejectsInvalidModuleInMetadata(t *testing.T) {
	payload := map[string]any{
		"id":             "cs_test_4",
		"customer_email": "test@example.com",
		"customer":       "cus_test_4",
		"payment_status": "paid",
		"amount_total":   7900,
		"metadata": map[string]string{
			"tier":    "developer",
			"modules": "hipaa,typo_module",
		},
	}
	data, _ := json.Marshal(payload)

	s := &Server{
		logger:       discardLogger(),
		licenseGen:   NewMockLicenseGenerator(),
		emailService: NewMockEmailService(),
	}
	err := s.handleCheckoutCompleted(data)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidModule) {
		t.Errorf("expected ErrInvalidModule, got %v", err)
	}
}

func TestHandleCheckoutCompleted_NoModules_StillWorks(t *testing.T) {
	// Plain tier upgrade, no modules. Should work exactly like v3.1.1.
	payload := map[string]any{
		"id":             "cs_test_5",
		"customer_email": "test@example.com",
		"customer":       "cus_test_5",
		"payment_status": "paid",
		"amount_total":   7900,
		"metadata":       map[string]string{"tier": "developer"},
	}
	data, _ := json.Marshal(payload)

	s := &Server{
		logger:       discardLogger(),
		licenseGen:   NewMockLicenseGenerator(),
		emailService: NewMockEmailService(),
	}
	if err := s.handleCheckoutCompleted(data); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// ---- MockLicenseGenerator.AddModules contract ----

func TestMockLicenseGenerator_AddModules_Success(t *testing.T) {
	mock := NewMockLicenseGenerator()
	key, _ := mock.GenerateLicense("cus_test", "developer", 365)

	err := mock.AddModules(key, "cus_test", []string{"hipaa", "pci"}, 19800)
	if err != nil {
		t.Errorf("AddModules: %v", err)
	}
}

func TestMockLicenseGenerator_AddModules_UnknownKey(t *testing.T) {
	mock := NewMockLicenseGenerator()
	err := mock.AddModules("AG-FAKE-123", "cus_test", []string{"hipaa"}, 9900)
	if err == nil {
		t.Error("expected error for unknown key, got nil")
	}
}

func TestMockLicenseGenerator_AddModules_NoModules(t *testing.T) {
	mock := NewMockLicenseGenerator()
	key, _ := mock.GenerateLicense("cus_test", "developer", 365)
	err := mock.AddModules(key, "cus_test", nil, 0)
	if err == nil {
		t.Error("expected error for empty modules list, got nil")
	}
}

func TestMockLicenseGenerator_AddModules_InvalidModule(t *testing.T) {
	mock := NewMockLicenseGenerator()
	key, _ := mock.GenerateLicense("cus_test", "developer", 365)
	err := mock.AddModules(key, "cus_test", []string{"bogus"}, 9900)
	if err == nil {
		t.Error("expected error for invalid module, got nil")
	}
}

// ---- cross-reference: license.IsValidModule matches the billing whitelist ----

func TestModuleWhitelistConsistency(t *testing.T) {
	// Every module name in license.AllModules should be parseable
	// from a "module_<name>" lookup_key.
	for _, m := range license.AllModules {
		t.Run(m, func(t *testing.T) {
			parsed := moduleFromLookupKey("module_" + m)
			if parsed != m {
				t.Errorf("roundtrip failed: moduleFromLookupKey(\"module_%s\") = %q, want %q", m, parsed, m)
			}
		})
	}
}

// ---- discardLogger ----

func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// ---- parseModulesFromSession: dedup across both shapes ----

func TestParseModulesFromSession_DedupAcrossShapes(t *testing.T) {
	// HIPAA appears in BOTH subscription_items and metadata.modules.
	// The seen-map should ensure it's only returned once.
	s := &Server{logger: discardLogger()}
	session := &CheckoutSession{
		SubscriptionItems: SubscriptionItemsWrapper{
			Data: []SubscriptionItem{
				{ID: "si_1", Price: SubscriptionItemPrice{LookupKey: "module_hipaa"}},
			},
		},
		Metadata: map[string]string{
			"modules": "hipaa,pci",
		},
	}
	modules, err := s.parseModulesFromSession(session)
	if err != nil {
		t.Fatalf("parseModulesFromSession: %v", err)
	}
	// Expect: hipaa (deduplicated), pci (from CSV).
	wantCount := 2
	if len(modules) != wantCount {
		t.Errorf("got %d modules %v, want %d (hipaa dedup'd from both shapes)", len(modules), modules, wantCount)
	}
}
