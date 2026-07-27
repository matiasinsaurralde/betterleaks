package detect

import "sort"

// newlineCache memoizes the newline offsets of a fragment's raw content so they
// are computed once per fragment instead of once per candidate rule. The offsets
// depend only on fragment.Raw, which is constant across every rule and every
// decode pass, so a single cache is valid for the whole detectFragment call.
// It is not safe for concurrent use, but each detectFragment call owns its own
// cache, so no fragment's cache is ever shared across goroutines.
type newlineCache struct {
	raw      string
	offsets  []int
	computed bool
}

func (c *newlineCache) get() []int {
	if !c.computed {
		c.offsets = findNewlineIndices(c.raw)
		c.computed = true
	}
	return c.offsets
}

// Location represents a location in a file
type Location struct {
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
	startLineIndex int
	endLineIndex   int
}

// location resolves the line/column span of a match given the byte offsets of
// every newline in raw. newlineOffsets must be sorted ascending (it always is,
// coming from findNewlineIndices).
//
// The previous implementation scanned the entire newlineOffsets slice for every
// match, making per-fragment work O(matches * newlines). Because the offsets are
// sorted, the start and end lines can be found with binary search in O(log n).
// The assignment logic below reproduces the original loop's semantics exactly
// (verified by a differential fuzz test in location_test.go).
func location(newlineOffsets []int, raw string, matchIndex []int) Location {
	var location Location

	start := matchIndex[0]
	end := matchIndex[1]

	location.startLineIndex = 0

	// Fixes: https://github.com/zricethezav/gitleaks/issues/1037
	// When a fragment does NOT have any newlines, a default "newline"
	// will be counted to make the subsequent location calculation logic work
	// for fragments with no newlines.
	if len(newlineOffsets) == 0 {
		newlineOffsets = []int{len(raw)}
	}

	n := len(newlineOffsets)
	prevAt := func(i int) int {
		if i == 0 {
			return 0
		}
		return newlineOffsets[i-1]
	}

	// START: the original loop sets the start line at the single index si where
	// prevNewLine <= start && start < newlineOffsets[si]. Those intervals
	// [prev, offset) partition [0, lastOffset), so si is the smallest index with
	// newlineOffsets[si] > start. The START block also (re)writes endLine and
	// endLineIndex at iteration si.
	si := sort.Search(n, func(i int) bool { return newlineOffsets[i] > start })
	lineSet := si < n
	if lineSet {
		prevNewLine := prevAt(si)
		location.startLine = si
		location.endLine = si
		location.startColumn = (start - prevNewLine) + 1
		location.startLineIndex = prevNewLine
		location.endLineIndex = newlineOffsets[si]
	}

	// END: the original loop sets the end line at the single index ej where
	// prevNewLine < end && end <= newlineOffsets[ej]; those intervals
	// (prev, offset] mean ej is the smallest index with newlineOffsets[ej] >= end,
	// provided end is strictly greater than the previous offset.
	//
	// The original processes lines in ascending order and the START block also
	// writes endLine/endLineIndex, so whichever of START (at si) and END (at ej)
	// runs at the *later* iteration wins for those two fields. endColumn is only
	// ever written by END. Reproduce that ordering here.
	ej := sort.Search(n, func(i int) bool { return newlineOffsets[i] >= end })
	if ej < n && end > prevAt(ej) {
		location.endColumn = (end - prevAt(ej))
		if !lineSet || ej >= si {
			location.endLine = ej
			location.endLineIndex = newlineOffsets[ej]
		}
	}

	if !lineSet {
		// if lines never get set then that means the secret is most likely
		// on the last line of the diff output and the diff output does not have
		// a newline
		prevNewLine := prevAt(n) // == newlineOffsets[n-1]
		location.startColumn = (start - prevNewLine) + 1
		location.endColumn = (end - prevNewLine)
		location.startLine = n
		location.endLine = n

		// search for new line byte index
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
