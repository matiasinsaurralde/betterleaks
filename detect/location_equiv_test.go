package detect

import (
	"math/rand"
	"strings"
	"testing"
)

// locationReference is a verbatim copy of the pre-optimization location()
// implementation (adapted to the flat []int newline representation). It is the
// oracle for TestLocationEquivalence, which proves the optimized binary-search
// location() is byte-for-byte equivalent across a large, edge-case-heavy input
// space. Keep this in sync with the documented semantics, never with location().
func locationReference(newlineOffsets []int, raw string, matchIndex []int) Location {
	var (
		prevNewLine int
		location    Location
		lineSet     bool
		_lineNum    int
	)

	start := matchIndex[0]
	end := matchIndex[1]

	location.startLineIndex = 0

	if len(newlineOffsets) == 0 {
		newlineOffsets = []int{len(raw)}
	}

	for lineNum, off := range newlineOffsets {
		_lineNum = lineNum
		newLineByteIndex := off
		if prevNewLine <= start && start < newLineByteIndex {
			lineSet = true
			location.startLine = lineNum
			location.endLine = lineNum
			location.startColumn = (start - prevNewLine) + 1
			location.startLineIndex = prevNewLine
			location.endLineIndex = newLineByteIndex
		}
		if prevNewLine < end && end <= newLineByteIndex {
			location.endLine = lineNum
			location.endColumn = (end - prevNewLine)
			location.endLineIndex = newLineByteIndex
		}
		prevNewLine = off
	}

	if !lineSet {
		location.startColumn = (start - prevNewLine) + 1
		location.endColumn = (end - prevNewLine)
		location.startLine = _lineNum + 1
		location.endLine = _lineNum + 1

		i := 0
		for end+i < len(raw) {
			if raw[end+i] == '\n' {
				break
			}
			if raw[end+i] == '\r' {
				break
			}
			i++
		}
		location.endLineIndex = end + i
	}
	return location
}

// TestLocationEquivalence proves the optimized binary-search location() is
// byte-for-byte equivalent to the original loop implementation across a large
// space of random raw strings and match spans, including edge cases (empty
// offsets, matches at/after the last newline, zero-length matches at newline
// boundaries, CRLF).
func TestLocationEquivalence(t *testing.T) {
	r := rand.New(rand.NewSource(1))

	corpora := []string{
		"",
		"\n",
		"no newlines at all here",
		"a\nb\nc\n",
		"\n\n\n",
		"line one\nline two\nline three\nlast",
		"trailing\n",
		"lead\nmid\r\nwin\r\n",
		strings.Repeat("x", 50) + "\n" + strings.Repeat("y", 50),
	}
	for i := 0; i < 200; i++ {
		var sb strings.Builder
		n := r.Intn(120)
		for j := 0; j < n; j++ {
			switch r.Intn(6) {
			case 0:
				sb.WriteByte('\n')
			case 1:
				sb.WriteByte('\r')
			default:
				sb.WriteByte(byte('a' + r.Intn(26)))
			}
		}
		corpora = append(corpora, sb.String())
	}

	total := 0
	for _, raw := range corpora {
		offs := findNewlineIndices(raw)
		maxIdx := len(raw)
		for start := 0; start <= maxIdx; start++ {
			ends := []int{start, start + 1, start + 3, maxIdx, maxIdx + 1}
			for _, end := range ends {
				if end < start {
					continue
				}
				if end > maxIdx {
					end = maxIdx
				}
				mi := []int{start, end}
				got := location(offs, raw, mi)
				want := locationReference(offs, raw, mi)
				if got != want {
					t.Fatalf("mismatch raw=%q start=%d end=%d\n got=%+v\nwant=%+v\noffs=%v", raw, start, end, got, want, offs)
				}
				total++
			}
		}
	}
	t.Logf("location() equivalence checks passed: %d cases", total)
}
