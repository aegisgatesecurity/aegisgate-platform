// SPDX-License-Identifier: Apache-2.0
//go:build !race

package email

import (
	"fmt"
	"net"
	"testing"
)

func portFromAddr(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	var port int
	_, _ = fmt.Sscanf(p, "%d", &port)
	return port
}

// TestSend_ImplicitTLS_WithAuth exercises the implicit TLS SMTP pipeline with auth.
func TestSend_ImplicitTLS_WithAuth(t *testing.T) {
	srv, err := NewMockSMTPServer()
	if err != nil {
		t.Fatalf("NewMockSMTPServer: %v", err)
	}
	defer srv.Close()

	cfg := Config{
		Host:      "localhost",
		Port:      portFromAddr(srv.TLSAddr),
		From:      "from@test.local",
		Username:  "user",
		Password:  "pass",
		UseTLS:    false,
		TLSConfig: srv.TLSConfig("localhost"),
	}

	client := NewEmailClient(cfg)
	msg := []byte("From: from@test.local\r\nTo: rcpt@test.local\r\nSubject: TLS Auth Test\r\n\r\nHello\r\n")

	err = client.send("rcpt@test.local", msg)
	if err != nil {
		t.Fatalf("send() implicit TLS+auth failed: %v", err)
	}

	if cnt := srv.MessageCount(); cnt != 1 {
		t.Errorf("MessageCount = %d, want 1", cnt)
	}
}

// TestSend_ImplicitTLS_NoAuth exercises the implicit TLS path without auth.
func TestSend_ImplicitTLS_NoAuth(t *testing.T) {
	srv, err := NewMockSMTPServer()
	if err != nil {
		t.Fatalf("NewMockSMTPServer: %v", err)
	}
	defer srv.Close()

	cfg := Config{
		Host:      "localhost",
		Port:      portFromAddr(srv.TLSAddr),
		From:      "from@test.local",
		UseTLS:    false,
		TLSConfig: srv.TLSConfig("localhost"),
	}

	client := NewEmailClient(cfg)
	msg := []byte("From: from@test.local\r\nTo: rcpt@test.local\r\nSubject: TLS No Auth Test\r\n\r\nHello no auth\r\n")

	err = client.send("rcpt@test.local", msg)
	if err != nil {
		t.Fatalf("send() implicit TLS no-auth failed: %v", err)
	}

	if cnt := srv.MessageCount(); cnt != 1 {
		t.Errorf("MessageCount = %d, want 1", cnt)
	}
}

// TestSend_PlainSMTP_WithAuth exercises the STARTTLS path with auth.
func TestSend_PlainSMTP_WithAuth(t *testing.T) {
	srv, err := NewMockSMTPServer()
	if err != nil {
		t.Fatalf("NewMockSMTPServer: %v", err)
	}
	defer srv.Close()

	cfg := Config{
		Host:     "localhost",
		Port:     portFromAddr(srv.PlainAddr),
		From:     "from@test.local",
		Username: "user",
		Password: "pass",
		UseTLS:   true,
	}

	client := NewEmailClient(cfg)
	msg := []byte("From: from@test.local\r\nTo: rcpt@test.local\r\nSubject: STARTTLS Test\r\n\r\nHello STARTTLS\r\n")

	err = client.send("rcpt@test.local", msg)
	if err != nil {
		t.Fatalf("send() STARTTLS+auth failed: %v", err)
	}

	if cnt := srv.MessageCount(); cnt != 1 {
		t.Errorf("MessageCount = %d, want 1", cnt)
	}
}

// TestSend_PlainSMTP_NoAuth exercises the STARTTLS path without auth.
func TestSend_PlainSMTP_NoAuth(t *testing.T) {
	srv, err := NewMockSMTPServer()
	if err != nil {
		t.Fatalf("NewMockSMTPServer: %v", err)
	}
	defer srv.Close()

	cfg := Config{
		Host:   "localhost",
		Port:   portFromAddr(srv.PlainAddr),
		From:   "from@test.local",
		UseTLS: true,
	}

	client := NewEmailClient(cfg)
	msg := []byte("From: from@test.local\r\nTo: rcpt@test.local\r\nSubject: Plain No Auth\r\n\r\nHello plain\r\n")

	err = client.send("rcpt@test.local", msg)
	if err != nil {
		t.Fatalf("send() STARTTLS no-auth failed: %v", err)
	}

	if cnt := srv.MessageCount(); cnt != 1 {
		t.Errorf("MessageCount = %d, want 1", cnt)
	}
}
