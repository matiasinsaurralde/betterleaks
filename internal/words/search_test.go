package words

import (
	"sort"
	"strings"
	"testing"
)

func TestHasMatchInList(t *testing.T) {
	tests := []struct {
		name   string
		word   string
		minLen int
		// want nil result
		wantNil bool
		// otherwise: expected unique words (order-independent)
		wantUniqueWords []string
		// and minimum number of total matches
		wantMinMatchCount int
	}{
		{
			name:    "empty string",
			word:    "",
			minLen:  3,
			wantNil: true,
		},
		{
			name:    "shorter than minLen",
			word:    "ab",
			minLen:  3,
			wantNil: true,
		},
		{
			name:    "no dictionary substring",
			word:    "xyzabc",
			minLen:  3,
			wantNil: true,
		},
		{
			name:              "exact word",
			word:              "pass",
			minLen:            3,
			wantUniqueWords:   []string{"pass"},
			wantMinMatchCount: 1,
		},
		{
			name:              "prefix and middle matches",
			word:              "password",
			minLen:            3,
			wantUniqueWords:   []string{"pass", "password", "sword", "word"},
			wantMinMatchCount: 4,
		},
		{
			name:              "match in middle",
			word:              "xxwordxx",
			minLen:            3,
			wantUniqueWords:   []string{"word"},
			wantMinMatchCount: 1,
		},
		{
			name:              "minLen filters shorter",
			word:              "word",
			minLen:            4,
			wantUniqueWords:   []string{"word"},
			wantMinMatchCount: 1,
		},
		{
			name:    "minLen 4 excludes 3-char match",
			word:    "aba",
			minLen:  4,
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasMatchInList(tt.word, tt.minLen)
			if tt.wantNil {
				if got != nil {
					t.Errorf("HasMatchInList() = %v, want nil", got)
				}
				if ContainsWord(tt.word, tt.minLen) {
					t.Errorf("ContainsWord() = true, want false")
				}
				return
			}
			if got == nil || len(got) == 0 {
				t.Fatalf("HasMatchInList() = nil, want result with UniqueWords %v", tt.wantUniqueWords)
			}
			if !ContainsWord(tt.word, tt.minLen) {
				t.Errorf("ContainsWord() = false, want true")
			}
			r := got[0]
			if r.WordCount < tt.wantMinMatchCount {
				t.Errorf("WordCount = %d, want at least %d", r.WordCount, tt.wantMinMatchCount)
			}
			sort.Strings(r.UniqueWords)
			wantSorted := make([]string, len(tt.wantUniqueWords))
			copy(wantSorted, tt.wantUniqueWords)
			sort.Strings(wantSorted)
			if len(r.UniqueWords) != len(wantSorted) {
				t.Errorf("UniqueWords = %v, want %v", r.UniqueWords, wantSorted)
			} else {
				for i := range wantSorted {
					if r.UniqueWords[i] != wantSorted[i] {
						t.Errorf("UniqueWords = %v, want %v", r.UniqueWords, wantSorted)
						break
					}
				}
			}
		})
	}
}

func BenchmarkContainsWordMiss(b *testing.B) {
	secret := "xK9mP2qR7vL4nW8sT1yU6zA3bC5dE0fG"
	b.ReportAllocs()
	for b.Loop() {
		if ContainsWord(secret, 5) {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkHasMatchInListMiss(b *testing.B) {
	secret := "xK9mP2qR7vL4nW8sT1yU6zA3bC5dE0fG"
	b.ReportAllocs()
	for b.Loop() {
		if HasMatchInList(secret, 5) != nil {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkContainsWordHit(b *testing.B) {
	secret := "xxpasswordxx" + strings.Repeat("z", 64)
	b.ReportAllocs()
	for b.Loop() {
		if !ContainsWord(secret, 5) {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkHasMatchInListHit(b *testing.B) {
	secret := "xxpasswordxx" + strings.Repeat("z", 64)
	b.ReportAllocs()
	for b.Loop() {
		if HasMatchInList(secret, 5) == nil {
			b.Fatal("expected hit")
		}
	}
}
