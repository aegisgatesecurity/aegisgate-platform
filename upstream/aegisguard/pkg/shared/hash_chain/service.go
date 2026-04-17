// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security (adapted from AegisGate Security)
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================

package hash_chain

// HashStore defines the interface for hash storage
type HashStore interface {
	// GetChain returns a hash chain for a feed
	GetChain(feedID string) (*HashChain, error)

	// StoreHash stores a hash in the chain
	StoreHash(feedID string, hash string, previousHash string) error

	// VerifyHash verifies a hash in the chain
	VerifyHash(feedID string, hash string, previousHash string) (bool, error)

	// GetChainHashes returns all hashes for a feed
	GetChainHashes(feedID string) ([]string, error)

	// DeleteFeedHashes deletes all hashes for a feed
	DeleteFeedHashes(feedID string) error

	// VerifyChain verifies the integrity of a hash chain
	VerifyChain(feedID string) (bool, error)
}
