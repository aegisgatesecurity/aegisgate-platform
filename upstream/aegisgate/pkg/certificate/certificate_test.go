// SPDX-License-Identifier: Apache-2.0
// AegisGate - Chatbot Security Gateway
// Copyright (c) 2026 John Colvin <john.colvin@securityfirm.com>
// See LICENSE file for details.

package certificate

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	manager := NewManager()
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
}

func TestManagerEnableDisable(t *testing.T) {
	manager := NewManager()

	manager.EnableAutoGenerate()
	if !manager.IsAutoGenerateEnabled() {
		t.Error("Expected auto-generation enabled")
	}

	manager.DisableAutoGenerate()
	if manager.IsAutoGenerateEnabled() {
		t.Error("Expected auto-generation disabled")
	}
}

func TestManagerCacheOperations(t *testing.T) {
	manager := NewManager()

	manager.ClearCache()
	count := manager.GetCertificateCount()
	if count != 0 {
		t.Errorf("Expected cache count 0, got %d", count)
	}
}

func TestGenerateRootCA(t *testing.T) {
	manager := NewManager()

	_, err := manager.GenerateSelfSigned()
	if err != nil {
		t.Errorf("GenerateSelfSigned() error = %v", err)
	}

	ca, err := manager.GetCACertificate()
	if err != nil {
		t.Errorf("GetCACertificate() error = %v", err)
	}
	if ca == nil {
		t.Error("Expected CA certificate to be returned")
	}
}

func TestGenerateServerCertificate(t *testing.T) {
	manager := NewManager()

	_, err := manager.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("Failed to generate self-signed CA: %v", err)
	}

	cert, err := manager.GenerateProxyCertificate("localhost")
	if err != nil {
		t.Errorf("GenerateProxyCertificate() error = %v", err)
	}
	if cert == nil {
		t.Error("Expected certificate to be returned")
	}
}

func TestSaveAndLoadCertificate(t *testing.T) {
	manager := NewManager()

	_, err := manager.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("Failed to generate self-signed CA: %v", err)
	}

	caCert, err := manager.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA cert: %v", err)
	}

	certFile := t.TempDir() + "/cert.pem"
	keyFile := t.TempDir() + "/key.pem"

	err = manager.Save(caCert, certFile, keyFile)
	if err != nil {
		t.Errorf("Save() error = %v", err)
	}
}

func TestGetCertificate(t *testing.T) {
	manager := NewManager()

	_, err := manager.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("Failed to generate self-signed CA: %v", err)
	}

	_, err = manager.GenerateProxyCertificate("localhost")
	if err != nil {
		t.Fatalf("Failed to generate proxy cert: %v", err)
	}

	cert, err := manager.GetCertificate("localhost")
	if err != nil {
		t.Errorf("GetCertificate() error = %v", err)
	}
	if cert == nil {
		t.Error("Expected certificate to be returned")
	}
}
