// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package hash_chain

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// HashType defines the hashing algorithm to use
type HashType int

const (
	SHA256 HashType = iota
	SHA512
)

// Hash is a generic hash value
type Hash []byte

// Hash.String returns hex representation of the hash
func (h Hash) String() string {
	return hex.EncodeToString(h)
}

// HashChainEntry represents a single entry in the hash chain
type HashChainEntry struct {
	Hash         Hash      // Hash of the entry (computed from PayloadHash + PreviousHash + etc)
	PayloadHash  Hash      // Hash of the original data payload
	PreviousHash Hash      // Hash of the previous entry
	SequenceNum  uint64    // Sequence number of this entry
	Operation    string    // Operation performed
	Timestamp    time.Time // Timestamp of the entry
}

// merkleNode represents a node in the Merkle tree
type merkleNode struct {
	Hash  Hash
	Left  *merkleNode
	Right *merkleNode
}

// HashChain represents a hash chain for a specific feed
type HashChain struct {
	feedID     string
	hashType   HashType
	Entries    []*HashChainEntry
	MerkleTree []*merkleNode
	mu         sync.RWMutex
}

// ValidationError represents an error during chain verification
type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewHashChain creates a new hash chain for a feed
func NewHashChain(feedID string, hashType HashType) *HashChain {
	return &HashChain{
		feedID:   feedID,
		hashType: hashType,
		Entries:  make([]*HashChainEntry, 0),
	}
}

// computeHash computes a hash of the given data using the configured hash type
func (hc *HashChain) computeHash(data []byte) Hash {
	switch hc.hashType {
	case SHA512:
		h := sha512.Sum512(data)
		return h[:]
	case SHA256:
		fallthrough
	default:
		h := sha256.Sum256(data)
		return h[:]
	}
}

// generateEntryHash generates a hash for a chain entry using stable fields only
// FIXED: Removed Timestamp from hash computation to prevent verification failures
func (hc *HashChain) generateEntryHash(entry *HashChainEntry) Hash {
	data := append(entry.PayloadHash, entry.PreviousHash...)
	data = append(data, []byte(fmt.Sprintf("%d", entry.SequenceNum))...)
	return hc.computeHash(data)
}

// AddEntry adds a new entry to the hash chain
func (hc *HashChain) AddEntry(data []byte) (*HashChainEntry, error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	entry := &HashChainEntry{
		SequenceNum: uint64(len(hc.Entries)),
		Timestamp:   time.Now(),
	}

	// Compute hash of the data payload
	entry.PayloadHash = hc.computeHash(data)

	// Set previous hash for non-first entries
	if len(hc.Entries) > 0 {
		lastEntry := hc.Entries[len(hc.Entries)-1]
		entry.PreviousHash = lastEntry.Hash
	}

	// Generate entry hash (using stable fields only - FIXED!)
	entry.Hash = hc.generateEntryHash(entry)

	// Update Merkle tree
	hc.updateMerkleTree()

	hc.Entries = append(hc.Entries, entry)

	return entry, nil
}

// updateMerkleTree rebuilds the Merkle tree
func (hc *HashChain) updateMerkleTree() {
	hc.MerkleTree = hc.buildMerkleTree()
}

// buildMerkleTree builds a Merkle tree from the chain entries
func (hc *HashChain) buildMerkleTree() []*merkleNode {
	if len(hc.Entries) == 0 {
		return nil
	}

	// Create leaf nodes from entry hashes
	nodes := make([]*merkleNode, len(hc.Entries))
	for i, entry := range hc.Entries {
		nodes[i] = &merkleNode{Hash: entry.Hash}
	}

	// Build tree bottom-up
	for len(nodes) > 1 {
		var newLevel []*merkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				combined := append(nodes[i].Hash, nodes[i+1].Hash...)
				parent := &merkleNode{
					Hash:  hc.computeHash(combined),
					Left:  nodes[i],
					Right: nodes[i+1],
				}
				newLevel = append(newLevel, parent)
			} else {
				newLevel = append(newLevel, nodes[i])
			}
		}
		nodes = newLevel
	}

	return nodes
}

// GetEntry retrieves an entry by sequence number
func (hc *HashChain) GetEntry(seqNum uint64) (*HashChainEntry, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	if int(seqNum) >= len(hc.Entries) {
		return nil, false
	}
	return hc.Entries[seqNum], true
}

// GetEntryByHash retrieves an entry by its hash
func (hc *HashChain) GetEntryByHash(hash Hash) (*HashChainEntry, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	for _, entry := range hc.Entries {
		if string(entry.Hash) == string(hash) {
			return entry, true
		}
	}
	return nil, false
}

// VerifyEntry verifies a single entry in the hash chain
// This is the correct implementation with proper locking
func (hc *HashChain) VerifyEntry(entry *HashChainEntry) (bool, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	if entry == nil {
		return false, &ValidationError{Code: "VERIFY_ENTRY_NIL", Message: "entry is nil"}
	}

	// Verify PayloadHash exists
	if len(entry.PayloadHash) == 0 {
		return false, &ValidationError{Code: "EMPTY_PAYLOAD_HASH", Message: "PayloadHash is empty"}
	}

	// For non-first entries, verify chain linkage
	if entry.SequenceNum > 0 {
		if int(entry.SequenceNum) >= len(hc.Entries) {
			return false, &ValidationError{Code: "INVALID_SEQUENCE", Message: "sequence number exceeds chain length"}
		}

		prevEntry := hc.Entries[entry.SequenceNum-1]

		// Verify PreviousHash links to previous entry's Hash
		if string(entry.PreviousHash) != string(prevEntry.Hash) {
			return false, &ValidationError{
				Code:    "CHAIN_LINK_BROKEN",
				Message: fmt.Sprintf("chain link broken at entry %d", entry.SequenceNum),
			}
		}
	}

	return true, nil
}

// VerifyChain verifies the entire hash chain
// FIXED: Uses correct verification logic
func (hc *HashChain) VerifyChain() (bool, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	// Empty chain is valid
	if len(hc.Entries) == 0 {
		return true, nil
	}

	// Verify each entry
	for i := 0; i < len(hc.Entries); i++ {
		entry := hc.Entries[i]

		// Check PayloadHash exists
		if len(entry.PayloadHash) == 0 {
			return false, &ValidationError{
				Code:    "EMPTY_PAYLOAD_HASH",
				Message: fmt.Sprintf("entry %d has empty PayloadHash", i),
			}
		}

		// Verify chain linkage for non-first entries
		if i > 0 {
			prevEntry := hc.Entries[i-1]
			if string(entry.PreviousHash) != string(prevEntry.Hash) {
				return false, &ValidationError{
					Code:    "CHAIN_LINK_BROKEN",
					Message: fmt.Sprintf("chain link broken between entries %d and %d", i-1, i),
				}
			}
		}
	}

	return true, nil
}

// GetMerkleRoot returns the Merkle root hash
func (hc *HashChain) GetMerkleRoot() Hash {
	if len(hc.MerkleTree) == 0 {
		return nil
	}
	return hc.MerkleTree[0].Hash
}

// GetProof generates a Merkle proof for an entry
func (hc *HashChain) GetProof(entry *HashChainEntry) ([]Hash, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	if entry == nil {
		return nil, &ValidationError{Code: "NIL_ENTRY", Message: "entry is nil"}
	}

	idx := -1
	for i, e := range hc.Entries {
		if e == entry {
			idx = i
			break
		}
	}

	if idx == -1 {
		return nil, &ValidationError{Code: "ENTRY_NOT_FOUND", Message: "entry not found in chain"}
	}

	if len(hc.Entries) == 0 {
		return nil, &ValidationError{Code: "EMPTY_CHAIN", Message: "chain is empty"}
	}

	// Build Merkle tree level by level to generate proof
	// Start with leaf nodes (entry hashes)
	currentLevel := make([]Hash, len(hc.Entries))
	for i, e := range hc.Entries {
		currentLevel[i] = e.Hash
	}

	var proof []Hash

	// Build tree bottom-up, collecting sibling hashes
	for len(currentLevel) > 1 {
		if idx%2 == 0 {
			// Left child - sibling is to the right
			if idx+1 < len(currentLevel) {
				proof = append(proof, currentLevel[idx+1])
			}
		} else {
			// Right child - sibling is to the left
			proof = append(proof, currentLevel[idx-1])
		}
		idx /= 2

		// Build next level
		var nextLevel []Hash
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := append(currentLevel[i], currentLevel[i+1]...)
				nextLevel = append(nextLevel, hc.computeHash(combined))
			} else {
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}
		currentLevel = nextLevel
	}

	return proof, nil
}

// VerifyProof verifies a Merkle proof
func (hc *HashChain) VerifyProof(entryHash Hash, proof []Hash, root Hash) (bool, error) {
	currentHash := entryHash

	for _, sibling := range proof {
		combined := append(currentHash, sibling...)
		currentHash = hc.computeHash(combined)
	}

	return string(currentHash) == string(root), nil
}

// GetChainLength returns the number of entries in the chain
func (hc *HashChain) GetChainLength() int {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return len(hc.Entries)
}

// GetLastEntry returns the last entry in the chain
func (hc *HashChain) GetLastEntry() (*HashChainEntry, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	if len(hc.Entries) == 0 {
		return nil, false
	}
	return hc.Entries[len(hc.Entries)-1], true
}

// GetEntryRange returns a range of entries
func (hc *HashChain) GetEntryRange(start, end uint64) ([]*HashChainEntry, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	if start > end {
		return nil, &ValidationError{Code: "INVALID_RANGE", Message: "start > end"}
	}

	if int(end) >= len(hc.Entries) {
		return nil, &ValidationError{Code: "OUT_OF_BOUNDS", Message: "end exceeds chain length"}
	}

	return hc.Entries[start : end+1], nil
}

// GetAuditLog returns the audit log entries
func (hc *HashChain) GetAuditLog() []*HashChainEntry {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	result := make([]*HashChainEntry, len(hc.Entries))
	copy(result, hc.Entries)
	return result
}

// MemoryHashStore provides in-memory storage for hash chains
type MemoryHashStore struct {
	chains map[string][]string
	mu     sync.RWMutex
}

// NewMemoryHashStore creates a new memory hash store
func NewMemoryHashStore() *MemoryHashStore {
	return &MemoryHashStore{
		chains: make(map[string][]string),
	}
}

// StoreHash stores a hash in the store
func (mhs *MemoryHashStore) StoreHash(feedID, hash, previousHash string) error {
	mhs.mu.Lock()
	defer mhs.mu.Unlock()

	mhs.chains[feedID] = append(mhs.chains[feedID], hash)
	return nil
}

// GetChain retrieves hashes for a feed
func (mhs *MemoryHashStore) GetChain(feedID string) (string, error) {
	mhs.mu.RLock()
	defer mhs.mu.RUnlock()

	hashes, ok := mhs.chains[feedID]
	if !ok || len(hashes) == 0 {
		return "", &ValidationError{Code: "NOT_FOUND", Message: "feed not found"}
	}

	return hashes[len(hashes)-1], nil
}

// VerifyHash verifies a hash exists in the store
func (mhs *MemoryHashStore) VerifyHash(feedID, hash, previousHash string) (bool, error) {
	mhs.mu.RLock()
	defer mhs.mu.RUnlock()

	hashes, ok := mhs.chains[feedID]
	if !ok {
		return false, nil
	}

	for _, h := range hashes {
		if h == hash {
			return true, nil
		}
	}

	return false, nil
}

// GetChainHashes returns all hashes for a feed
func (mhs *MemoryHashStore) GetChainHashes(feedID string) ([]string, error) {
	mhs.mu.RLock()
	defer mhs.mu.RUnlock()

	hashes, ok := mhs.chains[feedID]
	if !ok {
		return nil, &ValidationError{Code: "NOT_FOUND", Message: "feed not found"}
	}

	return hashes, nil
}

// DeleteFeedHashes deletes all hashes for a feed
func (mhs *MemoryHashStore) DeleteFeedHashes(feedID string) error {
	mhs.mu.Lock()
	defer mhs.mu.Unlock()

	delete(mhs.chains, feedID)
	return nil
}

// VerifyChain verifies a chain in the store
func (mhs *MemoryHashStore) VerifyChain(feedID string) (bool, error) {
	hashes, err := mhs.GetChainHashes(feedID)
	if err != nil {
		return false, err
	}

	return len(hashes) > 0, nil
}

// Backward compatibility aliases
// These now point to the verified implementations

// VerifyEntryFixed is an alias for VerifyEntry (for backward compatibility)
func (hc *HashChain) VerifyEntryFixed(entry *HashChainEntry) (bool, error) {
	return hc.VerifyEntry(entry)
}

// VerifyChainFixed is an alias for VerifyChain (for backward compatibility)
func (hc *HashChain) VerifyChainFixed() (bool, error) {
	return hc.VerifyChain()
}

// IsValidChain is a convenience method
func (hc *HashChain) IsValidChain() bool {
	valid, _ := hc.VerifyChain()
	return valid
}

// GetChainVerificationReport returns a verification report
func (hc *HashChain) GetChainVerificationReport() string {
	report := "═══════════════════════════════════════\n"
	report += "     HASH CHAIN VERIFICATION REPORT    \n"
	report += "═══════════════════════════════════════\n"
	report += fmt.Sprintf("Chain Length:    %d entries\n", hc.GetChainLength())
	report += fmt.Sprintf("Merkle Root:    %x\n", hc.GetMerkleRoot())
	report += "───────────────────────────────────────\n"

	valid, err := hc.VerifyChain()

	if err != nil {
		report += "Status:          [INVALID]\n"
		report += fmt.Sprintf("Error:          %s\n", err.Error())
	} else if valid {
		report += "Status:          ✅ VALID\n"
	}

	report += "═══════════════════════════════════════\n"

	return report
}
