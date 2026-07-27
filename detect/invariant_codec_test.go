package detect

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/detect/codec"
)

// encHex encodes to lowercase hex (>=32 chars => recognized as hex run).
func encHex(s string) string { return hex.EncodeToString([]byte(s)) }

// encB64 standard base64.
func encB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// encPercent percent-encodes every byte.
func encPercent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// encUnicodeEsc encodes each byte as \u00XX.
func encUnicodeEsc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, `\u%04X`, s[i])
	}
	return b.String()
}

// encUnicodeCP encodes each byte as U+00XX separated by spaces.
func encUnicodeCP(s string) string {
	parts := make([]string, len(s))
	for i := 0; i < len(s); i++ {
		parts[i] = fmt.Sprintf("U+%04X", s[i])
	}
	return strings.Join(parts, " ")
}

func randPrintable(r *rand.Rand, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte(0x21 + r.Intn(0x7e-0x21)))
	}
	return b.String()
}

// buildNested wraps a core payload in `depth` random encodings, embedding it
// inside surrounding random literal text at each level.
func buildNested(r *rand.Rand, depth int) string {
	core := randPrintable(r, 8+r.Intn(20))
	cur := core
	for d := 0; d < depth; d++ {
		switch r.Intn(5) {
		case 0:
			cur = encHex(cur)
		case 1:
			cur = encB64(cur)
		case 2:
			cur = encPercent(cur)
		case 3:
			cur = encUnicodeEsc(cur)
		case 4:
			cur = encUnicodeCP(cur)
		}
		// optionally surround with literal noise
		pre := randPrintable(r, r.Intn(6))
		post := randPrintable(r, r.Intn(6))
		sep := " "
		if r.Intn(2) == 0 {
			sep = ""
		}
		cur = pre + sep + cur + sep + post
	}
	return cur
}

// TestCodecOffsetInvariants drives the exact production offset-mapping and
// slicing path (mirrors detectFragmentWithRule's encoded branch) over every
// possible match sub-range at every decode pass, checking for panics / OOB.
func TestCodecOffsetInvariants(t *testing.T) {
	const maxDepth = 6
	r := rand.New(rand.NewSource(1))

	for iter := 0; iter < 20000; iter++ {
		raw := buildNested(r, 1+r.Intn(maxDepth))
		checkOne(t, raw)
	}
}

func checkOne(t *testing.T, raw string) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("PANIC on input %q: %v", raw, p)
		}
	}()

	newlineIdx := findNewlineIndices(raw)
	decoder := codec.NewDecoder()
	currentRaw := raw
	var segments []*codec.EncodedSegment
	depth := 0
	for {
		if len(segments) > 0 {
			n := len(currentRaw)
			// Sample match ranges. Include boundary-heavy ranges.
			for _, s := range sampleIdx(n) {
				for _, e := range sampleIdx(n) {
					if e <= s {
						continue
					}
					segs := codec.SegmentsWithDecodedOverlap(segments, s, e)
					if len(segs) == 0 {
						continue
					}
					// CurrentLine panic check
					_ = codec.CurrentLine(segs, currentRaw)
					// AdjustMatchIndex -> location -> Line slice (exact prod path)
					adj := codec.AdjustMatchIndex(segs, []int{s, e})
					if adj[0] < 0 || adj[1] < 0 || adj[0] > adj[1] {
						t.Fatalf("bad adjusted index %v for match [%d,%d] on raw=%q", adj, s, e, raw)
					}
					loc := location(newlineIdx, raw, adj)
					if adj[1] > loc.endLineIndex {
						loc.endLineIndex = adj[1]
					}
					if loc.startLineIndex < 0 || loc.endLineIndex > len(raw) || loc.startLineIndex > loc.endLineIndex {
						t.Fatalf("OOB Line slice raw[%d:%d] len=%d adj=%v match=[%d,%d] raw=%q",
							loc.startLineIndex, loc.endLineIndex, len(raw), adj, s, e, raw)
					}
					_ = raw[loc.startLineIndex:loc.endLineIndex]
				}
			}
		}
		depth++
		if depth > 5 {
			break
		}
		currentRaw, segments = decoder.Decode(currentRaw, segments)
		if len(segments) == 0 {
			break
		}
	}
}

// sampleIdx returns a set of interesting indices in [0,n].
func sampleIdx(n int) []int {
	if n == 0 {
		return []int{0}
	}
	set := map[int]struct{}{0: {}, n: {}}
	if n >= 1 {
		set[1] = struct{}{}
		set[n-1] = struct{}{}
	}
	set[n/2] = struct{}{}
	// a few random ones for larger inputs
	for i := 0; i < 4; i++ {
		set[i*n/5] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for k := range set {
		if k >= 0 && k <= n {
			out = append(out, k)
		}
	}
	return out
}
