//go:build cgo
// +build cgo

package ml

import (
	"testing"
)

func TestLRUCacheBasic(t *testing.T) {
	c := newMLLRUCache(100)

	ts := ThreatScore{Score: 0.95, IsThreat: true}
	c.Put(123, ts)

	got, ok := c.Get(123)
	if !ok {
		t.Fatal("cache miss after put")
	}
	if got.Score != 0.95 {
		t.Fatalf("wrong score: %f", got.Score)
	}

	_, ok = c.Get(999)
	if ok {
		t.Fatal("cache hit on non-existent key")
	}
}

func TestLRUCacheEviction(t *testing.T) {
	c := newMLLRUCache(3)
	c.Put(1, ThreatScore{Score: 1})
	c.Put(2, ThreatScore{Score: 2})
	c.Put(3, ThreatScore{Score: 3})
	c.Put(4, ThreatScore{Score: 4})

	_, ok := c.Get(1)
	if ok {
		t.Fatal("key 1 should have been evicted")
	}
	_, ok = c.Get(4)
	if !ok {
		t.Fatal("key 4 should exist")
	}
}

func TestHashInputML(t *testing.T) {
	h1 := hashInputML("hello world")
	h2 := hashInputML("hello world")
	h3 := hashInputML("helloWorld")

	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}
	if h1 == h3 {
		t.Fatal("different inputs should produce different hashes")
	}
}
