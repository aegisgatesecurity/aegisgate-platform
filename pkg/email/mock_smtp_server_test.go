// SPDX-License-Identifier: Apache-2.0
//go:build !race

package email

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// MockSMTPServer is a test SMTP server that supports both plain and TLS modes.
type MockSMTPServer struct {
	PlainAddr  string
	TLSAddr    string
	caCertPool *x509.CertPool
	plainLn    *net.TCPListener
	tlsLn      *net.TCPListener
	messages   [][]byte
	mu         sync.Mutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewMockSMTPServer creates a test SMTP server on available ports.
func NewMockSMTPServer() (*MockSMTPServer, error) {
	s := &MockSMTPServer{stopCh: make(chan struct{})}

	tlsCert, caPool, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	s.caCertPool = caPool

	plainAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	plainLn, err := net.ListenTCP("tcp", plainAddr)
	if err != nil {
		return nil, err
	}
	s.plainLn = plainLn
	s.PlainAddr = plainLn.Addr().String()

	tlsAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	tlsLnTCP, err := net.ListenTCP("tcp", tlsAddr)
	if err != nil {
		plainLn.Close()
		return nil, err
	}
	tlsLn := tls.NewListener(tlsLnTCP, &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	s.tlsLn = tlsLnTCP
	s.TLSAddr = tlsLn.Addr().String()

	s.wg.Add(2)
	go s.acceptLoop(plainLn)
	go s.acceptLoopTLS(tlsLn)

	time.Sleep(100 * time.Millisecond)

	return s, nil
}

func (s *MockSMTPServer) acceptLoop(ln *net.TCPListener) {
	defer s.wg.Done()
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		ln.SetDeadline(time.Now().Add(500 * time.Millisecond))
		conn, err := ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		go s.handleConn(conn)
	}
}

func (s *MockSMTPServer) acceptLoopTLS(ln net.Listener) {
	defer s.wg.Done()
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *MockSMTPServer) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("220 Mock SMTP Test Server\r\n"))
	r := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) == 0 {
			continue
		}
		switch {
		case line == "QUIT":
			conn.Write([]byte("221 Bye\r\n"))
			return
		case line == "RSET":
			conn.Write([]byte("250 OK\r\n"))
		case strings.HasPrefix(line, "EHLO") || strings.HasPrefix(line, "HELO"):
			conn.Write([]byte("250-Mock SMTP\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10240000\r\n"))
		case strings.HasPrefix(line, "AUTH"):
			s.handleAuth(line, r, conn)
		case strings.HasPrefix(line, "MAIL FROM"):
			conn.Write([]byte("250 OK\r\n"))
		case strings.HasPrefix(line, "RCPT TO"):
			conn.Write([]byte("250 OK\r\n"))
		case line == "DATA":
			conn.Write([]byte("354 Start mail input\r\n"))
			var msg []byte
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" || l == ".\r" {
					break
				}
				if len(l) >= 2 && l[0] == '.' && l[1] == '.' {
					l = l[1:]
				}
				msg = append(msg, l...)
			}
			s.mu.Lock()
			s.messages = append(s.messages, msg)
			s.mu.Unlock()
			conn.Write([]byte("250 OK: message queued\r\n"))
		default:
			conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func (s *MockSMTPServer) handleAuth(line string, r *bufio.Reader, conn net.Conn) {
	// Parse AUTH command: "AUTH <type>" or "AUTH <type> <initial-response>"
	parts := strings.SplitN(strings.TrimPrefix(line, "AUTH "), " ", 2)
	if len(parts) == 0 || parts[0] == "" {
		conn.Write([]byte("501 Syntax error in parameters\r\n"))
		return
	}
	authType := strings.TrimSpace(parts[0])
	switch authType {
	case "PLAIN":
		// If there's an initial response, use it; otherwise prompt
		if len(parts) >= 2 && parts[1] != "" {
			_, err := base64.StdEncoding.DecodeString(parts[1])
			if err == nil {
				conn.Write([]byte("235 Authentication successful\r\n"))
				return
			}
		}
		conn.Write([]byte("334 \r\n"))
		authLine, err := r.ReadString('\n')
		if err != nil {
			return
		}
		authLine = strings.TrimRight(authLine, "\r\n")
		_, err = base64.StdEncoding.DecodeString(authLine)
		if err == nil {
			conn.Write([]byte("235 Authentication successful\r\n"))
		} else {
			conn.Write([]byte("535 Authentication failed\r\n"))
		}
	case "LOGIN":
		conn.Write([]byte("334 VXNlcm5hbWU6\r\n"))
		_, _ = r.ReadString('\n')
		conn.Write([]byte("334 UGFzc3dvcmQ6\r\n"))
		_, _ = r.ReadString('\n')
		conn.Write([]byte("235 Authentication successful\r\n"))
	default:
		conn.Write([]byte("504 Unrecognized authentication type\r\n"))
	}
}

func (s *MockSMTPServer) Messages() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([][]byte, len(s.messages))
	copy(result, s.messages)
	return result
}

func (s *MockSMTPServer) MessageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *MockSMTPServer) TLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName: host,
		RootCAs:    s.caCertPool,
	}
}

func (s *MockSMTPServer) Close() {
	close(s.stopCh)
	s.plainLn.Close()
	s.tlsLn.Close()
	s.wg.Wait()
}

func generateSelfSignedCert() (tls.Certificate, *x509.CertPool, error) {
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
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	return tlsCert, certPool, err
}
