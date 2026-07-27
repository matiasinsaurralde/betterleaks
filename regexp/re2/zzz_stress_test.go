package re2

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	gore2 "github.com/betterleaks/go-re2"
)

// mimics detect.go slicing: currentRaw[matchIndex[0]:matchIndex[1]]
func checkIndices(t *testing.T, s string, idxs [][]int, tag string) {
	t.Helper()
	for _, m := range idxs {
		if len(m) < 2 {
			t.Fatalf("%s: short match %v", tag, m)
		}
		a, b := m[0], m[1]
		if a < 0 || b < 0 || a > len(s) || b > len(s) || a > b {
			t.Fatalf("%s: OUT OF BOUNDS index %v for len(s)=%d input=%q", tag, m, len(s), s)
		}
		_ = s[a:b] // would panic if OOB
	}
}

func TestStressConcurrentIndices(t *testing.T) {
	patterns := []string{
		`(?i)(?:key|token|secret)[a-z0-9_\-]*\s*[:=]\s*['"]?([a-z0-9\-_=]{8,64})['"]?`,
		`(\w+)@(\w+\.\w+)`,
		`[A-Za-z0-9+/]{20,}={0,2}`,
		`(a*)*b`,
		`(?:(.)(.))+`,
		`\b\w{3,}\b`,
		`(.+)=(.+)`,
	}

	// adversarial inputs: multibyte UTF-8, invalid UTF-8, NULs, long runs,
	// boundary-heavy, empty, near-4k.
	inputs := []string{
		"",
		"a",
		"key = 'abcdefghij'",
		strings.Repeat("é", 2000),                 // multibyte
		string([]byte{0xff, 0xfe, 0x00, 0x41, 0x00}), // invalid utf8 + NUL
		strings.Repeat("A", 4096) + "=" + strings.Repeat("B", 10),
		strings.Repeat("word ", 1000),
		"token: " + strings.Repeat("x", 100) + "\n" + strings.Repeat("é=v\n", 500),
		strings.Repeat("\x00", 500) + "secret=deadbeefcafebabe",
		strings.Repeat("ab", 5000),
	}

	for _, p := range patterns {
		re, err := gore2.Compile(p)
		if err != nil {
			t.Logf("skip pattern %q: %v", p, err)
			continue
		}
		var wg sync.WaitGroup
		for g := 0; g < 32; g++ {
			wg.Add(1)
			go func(seed int) {
				defer wg.Done()
				for iter := 0; iter < 200; iter++ {
					s := inputs[(seed+iter)%len(inputs)]
					idx := re.FindAllStringIndex(s, -1)
					checkIndices(t, s, idx, fmt.Sprintf("FindAllStringIndex p=%q", p))
					// FindStringSubmatch like detect.go on the secret
					_ = re.FindStringSubmatch(s)
					_ = re.MatchString(s)
					_ = re.ReplaceAllString(s, "X")
				}
			}(g)
		}
		wg.Wait()
	}
}
