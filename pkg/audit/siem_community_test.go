// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

func TestSIEMDispatcher_CommunityReturnsError(t *testing.T) {
	_, err := NewSIEMDispatcher(SIEMDispatcherConfig{})
	if err == nil {
		t.Fatal("expected ErrSIEMEnterpriseOnly, got nil")
	}
	if !errors.Is(err, ErrSIEMEnterpriseOnly) {
		t.Fatalf("expected ErrSIEMEnterpriseOnly, got %v", err)
	}
}

func TestSIEMDispatcher_CommunityNoOps(t *testing.T) {
	d := &SIEMDispatcher{}
	// Run and Stop should be safe no-ops
	d.Run(context.Background())
	d.Stop()
	stats := d.Stats()
	if stats.EventsPolled != 0 || stats.EventsForwarded != 0 {
		t.Errorf("community SIEMDispatcher stats should be zero-valued: %+v", stats)
	}
}

func TestLoggingEventAdapter(t *testing.T) {
	now := time.Now().UTC()
	ev := logging.Event{
		ID:       "evt-123",
		Time:     now,
		Type:     "auth",
		Action:   "login",
		Severity: logging.SeverityInfo,
		User:     "alice",
		Message:  "user logged in",
	}
	a := loggingEventAdapter{e: ev}

	if a.GetID() != "evt-123" {
		t.Errorf("GetID() = %q, want %q", a.GetID(), "evt-123")
	}
	if !a.GetTime().Equal(now) {
		t.Errorf("GetTime() = %v, want %v", a.GetTime(), now)
	}
	if a.GetType() != "auth" {
		t.Errorf("GetType() = %q, want %q", a.GetType(), "auth")
	}
	if a.GetAction() != "login" {
		t.Errorf("GetAction() = %q, want %q", a.GetAction(), "login")
	}
	if a.GetSeverity() != "info" {
		t.Errorf("GetSeverity() = %q, want %q", a.GetSeverity(), "info")
	}
	if a.GetUser() != "alice" {
		t.Errorf("GetUser() = %q, want %q", a.GetUser(), "alice")
	}
	if a.GetMessage() != "user logged in" {
		t.Errorf("GetMessage() = %q, want %q", a.GetMessage(), "user logged in")
	}
}

func TestAdaptedLen(t *testing.T) {
	events := []loggingEvent{
		loggingEventAdapter{e: logging.Event{ID: "a"}},
		loggingEventAdapter{e: logging.Event{ID: "b"}},
		loggingEventAdapter{e: logging.Event{ID: "c"}},
	}
	if n := adaptedLen(events); n != 3 {
		t.Errorf("adaptedLen() = %d, want 3", n)
	}
	if n := adaptedLen(nil); n != 0 {
		t.Errorf("adaptedLen(nil) = %d, want 0", n)
	}
}
