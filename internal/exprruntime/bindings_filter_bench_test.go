package exprruntime

import (
	"fmt"
	"strings"
	"testing"
)

func TestContainsAnyEarlyExit(t *testing.T) {
	terms := []string{"alpha", "bravo", "charlie", "delta"}
	if !containsAny("xxbravoyy", terms) {
		t.Fatal("expected hit on lowercased haystack")
	}
	if !containsAny("xxBRAVOyy", terms) {
		t.Fatal("expected hit after ToLower haystack")
	}
	// Legacy semantics: uppercase patterns do not match a lowercased haystack.
	if containsAny("api_key", []string{"API"}) {
		t.Fatal("uppercase pattern must not match lowercased haystack")
	}
	if containsAny("nope", terms) {
		t.Fatal("expected miss")
	}
}

func BenchmarkContainsAnyMiss(b *testing.B) {
	terms := make([]string, 200)
	for i := range terms {
		terms[i] = fmt.Sprintf("stopword%04d", i)
	}
	haystack := strings.Repeat("zzzz", 64)
	// Warm the trie cache once outside the timed loop.
	_ = containsAny(haystack, terms)
	b.ReportAllocs()
	for b.Loop() {
		if containsAny(haystack, terms) {
			b.Fatal("unexpected hit")
		}
	}
}
