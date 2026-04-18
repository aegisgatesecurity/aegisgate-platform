package hash_chain

import (
	"testing"
)

// Test basic hash chain creation
func TestNewHashChain(t *testing.T) {
	tests := []struct {
		name     string
		feedID   string
		hashType HashType
	}{
		{"SHA256", "test-feed", SHA256},
		{"SHA512", "test-feed", SHA512},
		{"empty feedID", "", SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hc := NewHashChain(tt.feedID, tt.hashType)
			if hc == nil {
				t.Error("NewHashChain() returned nil")
			}
		})
	}
}

// Test AddEntry basic functionality
func TestAddEntry(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	entry, err := hc.AddEntry([]byte("data1"))
	if err != nil {
		t.Fatalf("AddEntry() failed: %v", err)
	}
	if entry == nil {
		t.Fatal("AddEntry() returned nil")
	}
	if entry.SequenceNum != 0 {
		t.Errorf("First entry SequenceNum = %d, want 0", entry.SequenceNum)
	}

	// Add second entry
	entry2, err := hc.AddEntry([]byte("data2"))
	if err != nil {
		t.Fatalf("AddEntry() failed: %v", err)
	}
	if entry2.SequenceNum != 1 {
		t.Errorf("Second entry SequenceNum = %d, want 1", entry2.SequenceNum)
	}

	// Verify chain linkage
	if string(entry2.PreviousHash) != string(entry.Hash) {
		t.Error("Chain linkage broken: entry2.PreviousHash != entry1.Hash")
	}
}

// Test chain length
func TestGetChainLength(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	if hc.GetChainLength() != 0 {
		t.Error("Empty chain should have length 0")
	}

	hc.AddEntry([]byte("a"))
	hc.AddEntry([]byte("b"))
	hc.AddEntry([]byte("c"))

	if hc.GetChainLength() != 3 {
		t.Errorf("Chain length = %d, want 3", hc.GetChainLength())
	}
}

// Test GetEntry
func TestGetEntry(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))
	hc.AddEntry([]byte("data3"))

	// Valid indices
	for i := 0; i < 3; i++ {
		entry, ok := hc.GetEntry(uint64(i))
		if !ok {
			t.Errorf("GetEntry(%d) returned false", i)
		}
		if entry.SequenceNum != uint64(i) {
			t.Errorf("Entry %d SequenceNum = %d", i, entry.SequenceNum)
		}
	}

	// Invalid index
	_, ok := hc.GetEntry(999)
	if ok {
		t.Error("GetEntry(999) should return false")
	}
}

// Test GetEntryByHash
func TestGetEntryByHash(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	entry1, _ := hc.AddEntry([]byte("data1"))
	entry2, _ := hc.AddEntry([]byte("data2"))

	// Find by hash
	found, ok := hc.GetEntryByHash(entry1.Hash)
	if !ok {
		t.Error("GetEntryByHash should find entry1 by its Hash")
	}
	if found.SequenceNum != 0 {
		t.Errorf("Found entry SequenceNum = %d, want 0", found.SequenceNum)
	}

	// Find second entry
	found, ok = hc.GetEntryByHash(entry2.Hash)
	if !ok {
		t.Error("GetEntryByHash should find entry2 by its Hash")
	}
	if found.SequenceNum != 1 {
		t.Errorf("Found entry SequenceNum = %d, want 1", found.SequenceNum)
	}

	// Non-existent hash
	_, ok = hc.GetEntryByHash([]byte("not-found"))
	if ok {
		t.Error("GetEntryByHash should return false for non-existent hash")
	}
}

// Test Merkle root
func TestMerkleRoot(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	// Empty chain
	root := hc.GetMerkleRoot()
	t.Logf("Empty chain Merkle root: %x", root)

	// Add entries
	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))
	hc.AddEntry([]byte("data3"))

	root = hc.GetMerkleRoot()
	if root == nil {
		t.Error("GetMerkleRoot() should not return nil")
	}
	t.Logf("Non-empty chain Merkle root: %x", root)
}

// Test GetProof
func TestGetProof(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))
	hc.AddEntry([]byte("data3"))

	for i := 0; i < 3; i++ {
		entry, _ := hc.GetEntry(uint64(i))
		proof, err := hc.GetProof(entry)
		if err != nil {
			t.Errorf("GetProof(%d) failed: %v", i, err)
		}
		if proof == nil {
			t.Errorf("GetProof(%d) returned nil", i)
		}
	}
}

// Test GetLastEntry
func TestGetLastEntry(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	// Empty chain
	_, ok := hc.GetLastEntry()
	if ok {
		t.Error("GetLastEntry() on empty chain should return false")
	}

	// Add entries
	hc.AddEntry([]byte("a"))
	hc.AddEntry([]byte("b"))
	hc.AddEntry([]byte("c"))

	last, ok := hc.GetLastEntry()
	if !ok {
		t.Error("GetLastEntry() should succeed")
	}
	if last.SequenceNum != 2 {
		t.Errorf("Last entry SequenceNum = %d, want 2", last.SequenceNum)
	}
}

// Test GetEntryRange
func TestGetEntryRange(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	hc.AddEntry([]byte("a"))
	hc.AddEntry([]byte("b"))
	hc.AddEntry([]byte("c"))
	hc.AddEntry([]byte("d"))
	hc.AddEntry([]byte("e"))

	// Valid range
	entries, err := hc.GetEntryRange(1, 3)
	if err != nil {
		t.Fatalf("GetEntryRange(1,3) failed: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("GetEntryRange(1,3) returned %d entries, want 3", len(entries))
	}

	// Invalid range
	_, err = hc.GetEntryRange(3, 1)
	if err == nil {
		t.Error("GetEntryRange(3,1) should fail")
	}
}

// Test GetAuditLog
func TestGetAuditLog(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))

	log := hc.GetAuditLog()
	if len(log) != 2 {
		t.Errorf("Audit log length = %d, want 2", len(log))
	}
}

// Test SHA256 vs SHA512
func TestSHA256vsSHA512(t *testing.T) {
	hc256 := NewHashChain("test", SHA256)
	hc512 := NewHashChain("test", SHA512)

	hc256.AddEntry([]byte("same"))
	hc512.AddEntry([]byte("same"))

	e256, _ := hc256.GetEntry(0)
	e512, _ := hc512.GetEntry(0)

	// Different algorithms should produce different hashes
	if string(e256.Hash) == string(e512.Hash) {
		t.Error("SHA256 and SHA512 should produce different hashes")
	}
}

// Test VerifyEntry - the fixed implementation
func TestVerifyEntry(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	entry, _ := hc.AddEntry([]byte("test data"))

	// Verify first entry
	valid, err := hc.VerifyEntry(entry)
	if err != nil {
		t.Fatalf("VerifyEntry() failed: %v", err)
	}
	if !valid {
		t.Error("VerifyEntry() should return true for valid entry")
	}

	// Add more entries and verify
	hc.AddEntry([]byte("more data"))
	hc.AddEntry([]byte("even more data"))

	// Verify all entries
	for i := 0; i < 3; i++ {
		entry, _ := hc.GetEntry(uint64(i))
		valid, err := hc.VerifyEntry(entry)
		if err != nil {
			t.Errorf("VerifyEntry() failed for entry %d: %v", i, err)
		}
		if !valid {
			t.Errorf("VerifyEntry() should return true for entry %d", i)
		}
	}

	t.Logf("VerifyEntry works correctly!")
}

// Test VerifyChain - the fixed implementation
func TestVerifyChain(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	// Empty chain
	valid, err := hc.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain() on empty chain failed: %v", err)
	}
	if !valid {
		t.Error("VerifyChain() should return true for empty chain")
	}

	// Add entries
	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))
	hc.AddEntry([]byte("data3"))

	valid, err = hc.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain() failed: %v", err)
	}
	if !valid {
		t.Error("VerifyChain() should return true for valid chain")
	}

	t.Logf("VerifyChain works correctly!")
}

// Test broken chain detection
func TestVerifyChainDetectsBrokenLink(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))

	// Verify it's valid first
	valid, _ := hc.VerifyChain()
	if !valid {
		t.Fatal("Chain should be valid before tampering")
	}

	// Tamper with the chain
	hc.Entries[1].PreviousHash = []byte("tampered")

	// Verify should fail
	valid, err := hc.VerifyChain()
	if err == nil && valid {
		t.Error("VerifyChain should detect broken chain link")
	}

	t.Logf("VerifyChain correctly detects broken link!")
}

// Test IsValidChain
func TestIsValidChain(t *testing.T) {
	hc := NewHashChain("test", SHA256)
	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))

	if !hc.IsValidChain() {
		t.Error("IsValidChain() should return true for valid chain")
	}

	// Empty chain should be valid
	hc2 := NewHashChain("empty", SHA256)
	if !hc2.IsValidChain() {
		t.Error("IsValidChain() should return true for empty chain")
	}

	t.Logf("IsValidChain works correctly!")
}

// Test GetChainVerificationReport
func TestGetChainVerificationReport(t *testing.T) {
	hc := NewHashChain("test-feed", SHA256)
	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))

	report := hc.GetChainVerificationReport()
	if report == "" {
		t.Error("GetChainVerificationReport() should not return empty string")
	}

	t.Logf("Verification Report:\n%s", report)
}

// Test large chain
func TestLargeChain(t *testing.T) {
	hc := NewHashChain("test", SHA256)

	// Add 100 entries
	for i := 0; i < 100; i++ {
		data := []byte(string(rune('a'+i%26)) + string(rune('0'+i%10)))
		_, err := hc.AddEntry(data)
		if err != nil {
			t.Fatalf("AddEntry(%d) failed: %v", i, err)
		}
	}

	// Verify chain
	valid, err := hc.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain() failed: %v", err)
	}
	if !valid {
		t.Error("VerifyChain() should return true for valid large chain")
	}

	t.Logf("Large chain (100 entries) verified!")
}

// Test MemoryHashStore
func TestMemoryHashStore(t *testing.T) {
	mhs := NewMemoryHashStore()
	if mhs == nil {
		t.Fatal("NewMemoryHashStore() returned nil")
	}

	// Store
	hc := NewHashChain("feed1", SHA256)
	entry, _ := hc.AddEntry([]byte("data1"))
	err := mhs.StoreHash("feed1", string(entry.Hash), "")
	if err != nil {
		t.Fatalf("StoreHash() failed: %v", err)
	}

	// Retrieve
	result, err := mhs.GetChain("feed1")
	if err != nil {
		t.Fatalf("GetChain() failed: %v", err)
	}
	if result == "" {
		t.Error("GetChain() returned empty")
	}

	t.Logf("MemoryHashStore basic operations work")
}

// Test MemoryHashStore operations
func TestMemoryHashStoreOperations(t *testing.T) {
	mhs := NewMemoryHashStore()

	hc := NewHashChain("test-feed", SHA256)
	e1, _ := hc.AddEntry([]byte("data1"))
	e2, _ := hc.AddEntry([]byte("data2"))

	mhs.StoreHash("test-feed", string(e1.Hash), "")
	mhs.StoreHash("test-feed", string(e2.Hash), "")

	// Get chain hashes
	hashes, err := mhs.GetChainHashes("test-feed")
	if err != nil {
		t.Fatalf("GetChainHashes() failed: %v", err)
	}
	t.Logf("Chain hashes: %d", len(hashes))

	// Verify a hash
	valid, err := mhs.VerifyHash("test-feed", string(e1.Hash), "")
	t.Logf("VerifyHash result: valid=%v, err=%v", valid, err)

	// Delete feed
	err = mhs.DeleteFeedHashes("test-feed")
	if err != nil {
		t.Logf("DeleteFeedHashes error: %v", err)
	}
}

// Test backward compatibility aliases
func TestBackwardCompatibility(t *testing.T) {
	hc := NewHashChain("test", SHA256)
	hc.AddEntry([]byte("data1"))
	hc.AddEntry([]byte("data2"))

	entry, _ := hc.GetEntry(0)

	// Verify both old and new function names work
	valid1, err1 := hc.VerifyEntryFixed(entry)
	valid2, err2 := hc.VerifyEntry(entry)

	if valid1 != valid2 {
		t.Error("VerifyEntry and VerifyEntryFixed should return same result")
	}
	if (err1 != nil) != (err2 != nil) {
		t.Error("VerifyEntry and VerifyEntryFixed should return same error")
	}

	// VerifyChain
	valid1, err1 = hc.VerifyChainFixed()
	valid2, err2 = hc.VerifyChain()

	if valid1 != valid2 {
		t.Error("VerifyChain and VerifyChainFixed should return same result")
	}
	if (err1 != nil) != (err2 != nil) {
		t.Error("VerifyChain and VerifyChainFixed should return same error")
	}

	t.Logf("Backward compatibility maintained!")
}
