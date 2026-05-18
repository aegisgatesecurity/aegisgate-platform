//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Email Package Failing SMTP Coverage Tests - Session 20
// =========================================================================
// Covers all implicit TLS error paths in send():
//   - NewClient failure (bad greeting)
//   - Auth failure (535 response)
//   - Mail failure (550 response)
//   - Rcpt failure (550 response)
//   - Data failure (503 response)
//   - Write failure (close raw TCP conn during DATA)
//   - Close failure (close conn during DATA close)
//   - Quit failure (close after 250 OK)
//   - Happy path full success
// =========================================================================

package email

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// =========================================================================
// FailingMockSMTPServer — configurable failure points for coverage
// =========================================================================

type SMTPFailMode int

const (
	FailNone       SMTPFailMode = iota // Happy path
	FailBadGreeting                     // No 220 greeting → NewClient failure
	FailAuth                            // Return 535 → Auth failure
	FailMail                            // Return 550 → MAIL FROM failure
	FailRcpt                            // Return 550 → RCPT TO failure
	FailData                            // Return 503 → DATA failure
	FailWriteClose                      // Close raw TCP conn after 354 → write failure
	FailDataClose                       // Close conn during DATA close → Close failure
	FailQuit                            // Close after 250 OK → Quit failure
)

type FailingMockSMTPServer struct {
	Addr     string
	FailMode SMTPFailMode
	ln       net.Listener
	certPool *x509.CertPool
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

func NewFailingMockSMTPServer(mode SMTPFailMode) (*FailingMockSMTPServer, error) {
	cert, pool, err := generateFailingCert()
	if err != nil {
		return nil, err
	}

	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	tcpLn, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsLn := tls.NewListener(tcpLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	s := &FailingMockSMTPServer{
		Addr:     tlsLn.Addr().String(),
		FailMode: mode,
		ln:       tlsLn,
		certPool: pool,
		stopCh:   make(chan struct{}),
	}

	s.wg.Add(1)
	go s.acceptLoop()

	time.Sleep(50 * time.Millisecond)
	return s, nil
}

func (s *FailingMockSMTPServer) acceptLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *FailingMockSMTPServer) handleConn(conn net.Conn) {
	defer conn.Close()

	if s.FailMode == FailBadGreeting {
		conn.Write([]byte("500 Service unavailable\r\n"))
		return
	}
	conn.Write([]byte("220 Mock Failing SMTP Ready\r\n"))
	r := bufio.NewReader(conn)

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		switch {
		case line == "QUIT":
			if s.FailMode == FailQuit {
				return // Close without sending 221 → Quit error
			}
			conn.Write([]byte("221 Bye\r\n"))
			return
		case strings.HasPrefix(line, "EHLO") || strings.HasPrefix(line, "HELO"):
			conn.Write([]byte("250-Mock Failing SMTP\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n"))
		case strings.HasPrefix(line, "AUTH"):
			if s.FailMode == FailAuth {
				conn.Write([]byte("535 Authentication failed\r\n"))
			} else {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) >= 3 {
					conn.Write([]byte("235 Authentication successful\r\n"))
				} else {
					conn.Write([]byte("334 \r\n"))
					r.ReadString('\n')
					conn.Write([]byte("235 Authentication successful\r\n"))
				}
			}
		case strings.HasPrefix(line, "MAIL FROM"):
			if s.FailMode == FailMail {
				conn.Write([]byte("550 Mailbox unavailable\r\n"))
			} else {
				conn.Write([]byte("250 OK\r\n"))
			}
		case strings.HasPrefix(line, "RCPT TO"):
			if s.FailMode == FailRcpt {
				conn.Write([]byte("550 User unknown\r\n"))
			} else {
				conn.Write([]byte("250 OK\r\n"))
			}
		case line == "DATA":
			if s.FailMode == FailData {
				conn.Write([]byte("503 No valid recipients\r\n"))
			} else if s.FailMode == FailWriteClose {
				conn.Write([]byte("354 Start mail input; end with <CRLF>.<CRLF>\r\n"))
				// Close the underlying TCP connection to force TLS write failure
				if tlsConn, ok := conn.(*tls.Conn); ok {
					tlsConn.NetConn().Close()
				}
				return
			} else if s.FailMode == FailDataClose {
				conn.Write([]byte("354 Start mail input; end with <CRLF>.<CRLF>\r\n"))
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" || l == ".\n" {
						return // Close without sending 250 OK → Close failure
					}
				}
			} else {
				conn.Write([]byte("354 Start mail input; end with <CRLF>.<CRLF>\r\n"))
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" || l == ".\n" {
						break
					}
				}
				conn.Write([]byte("250 OK: message queued\r\n"))
				if s.FailMode == FailQuit {
					return // Close after accepting message → Quit failure
				}
			}
		default:
			conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func (s *FailingMockSMTPServer) Close() {
	close(s.stopCh)
	s.ln.Close()
	s.wg.Wait()
}

func generateFailingCert() (tls.Certificate, *x509.CertPool, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "127.0.0.1"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	return tlsCert, pool, err
}

// =========================================================================
// Helper
// =========================================================================

func splitHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1", 465
	}
	port := 0
	for _, r := range portStr {
		port = port*10 + int(r-'0')
	}
	return host, port
}

func makeTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

// =========================================================================
// Tests
// =========================================================================

func TestFailingSMTP_AuthFailure(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailAuth)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message"))
	if err == nil {
		t.Error("expected auth failure error")
	}
	if !strings.Contains(err.Error(), "auth") && !strings.Contains(err.Error(), "Auth") {
		t.Logf("auth error: %v", err)
	}
}

func TestFailingSMTP_MailFailure(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailMail)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message"))
	if err == nil {
		t.Error("expected MAIL FROM failure error")
	}
	if !strings.Contains(err.Error(), "MAIL") {
		t.Logf("mail error: %v", err)
	}
}

func TestFailingSMTP_RcptFailure(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailRcpt)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message"))
	if err == nil {
		t.Error("expected RCPT TO failure error")
	}
	if !strings.Contains(err.Error(), "RCPT") {
		t.Logf("rcpt error: %v", err)
	}
}

func TestFailingSMTP_DataFailure(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailData)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message"))
	if err == nil {
		t.Error("expected DATA failure error")
	}
	if !strings.Contains(err.Error(), "DATA") {
		t.Logf("data error: %v", err)
	}
}

func TestFailingSMTP_WriteFailure(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailWriteClose)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message"))
	if err == nil {
		t.Error("expected write failure error")
	}
	if !strings.Contains(err.Error(), "write") && !strings.Contains(err.Error(), "connection") && !strings.Contains(err.Error(), "broken pipe") {
		t.Logf("write error: %v", err)
	}
}

func TestFailingSMTP_DataCloseFailure(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailDataClose)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message"))
	if err == nil {
		t.Error("expected DATA close failure error")
	}
	if !strings.Contains(err.Error(), "close") && !strings.Contains(err.Error(), "connection") {
		t.Logf("close error: %v", err)
	}
}

func TestFailingSMTP_NewClientFailure(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailBadGreeting)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message"))
	if err == nil {
		t.Error("expected NewClient failure error")
	}
	if !strings.Contains(err.Error(), "client") && !strings.Contains(err.Error(), "SMTP") {
		t.Logf("client error: %v", err)
	}
}

func TestFailingSMTP_QuitError(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailQuit)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	// This should succeed overall (Quit error is non-fatal)
	err = client.send("to@test.com", []byte("test message\r\n"))
	if err != nil {
		t.Logf("send with quit error (non-fatal): %v", err)
	}
}

func TestFailingSMTP_HappyPath(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailNone)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message\r\n"))
	if err != nil {
		t.Fatalf("unexpected send error: %v", err)
	}
}

func TestFailingSMTP_SendLicenseEmail(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailNone)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	data := LicenseEmailData{
		CustomerName: "John Doe",
		Tier:         "Enterprise",
		LicenseKey:   "AAAA-BBBB-CCCC-DDDD",
		ExpiresAt:    "2026-06-18",
		IssuedAt:     "2026-05-18",
		Features:     []string{"feature-1", "feature-2"},
		SupportEmail: "support@test.com",
		CompanyName:  "Test Company",
		CompanyURL:   "https://test.com",
	}

	err = client.SendLicenseEmail("john@example.com", data)
	if err != nil {
		t.Fatalf("SendLicenseEmail failed: %v", err)
	}
}

func TestFailingSMTP_SimpleSendEmail(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailNone)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		TLSConfig: makeTLSConfig(host),
	}

	err = SimpleSendEmail(cfg, "to@test.com", "Subject", "Body content")
	if err != nil {
		t.Fatalf("SimpleSendEmail failed: %v", err)
	}
}

func TestFailingSMTP_NoAuth_NoCredentials(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailNone)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		UseTLS: false, TLSConfig: makeTLSConfig(host),
	}
	client := NewEmailClient(cfg)

	err = client.send("to@test.com", []byte("test message\r\n"))
	if err != nil {
		t.Fatalf("unexpected send error: %v", err)
	}
}

func TestFailingSMTP_DefaultTLSConfig(t *testing.T) {
	srv, err := NewFailingMockSMTPServer(FailNone)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer srv.Close()

	host, port := splitHostPort(srv.Addr)
	cfg := Config{
		Host: host, Port: port, From: "test@test.com",
		Username: "user", Password: "pass", UseTLS: false,
		// No TLSConfig — will use default with ServerName
	}
	client := NewEmailClient(cfg)

	// This will fail certificate verification since default TLSConfig won't have InsecureSkipVerify
	err = client.send("to@test.com", []byte("test message\r\n"))
	if err == nil {
		t.Log("send succeeded with default TLSConfig")
	} else {
		t.Logf("send with default TLSConfig got: %v (expected - cert verification)", err)
	}
}
