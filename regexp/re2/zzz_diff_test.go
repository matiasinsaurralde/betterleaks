package re2

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	gore2 "github.com/betterleaks/go-re2"
)

func TestDiffAgainstStdlib(t *testing.T) {
	patterns := []string{
		`secret`,
		`(?i)secret`,
		`[a-z0-9]{8,}`,
		`\bAKIA[0-9A-Z]{16}\b`,
		`key\s*=\s*"([^"]+)"`,
		`\d+`,
		`.`,
		`x`,
		`ab`,
		`(?i)password`,
	}
	mk := func() []string {
		var in []string
		in = append(in,
			"",
			"secret",
			"a secret value",
			"SECRET",
			"key = \"abcdef123456\"",
			"AKIAABCDEFGHIJKLMNOP end",
			"password: hunter2",
		)
		// NUL-embedded: secret hidden after a NUL byte
		in = append(in, "before\x00secret\x00after")
		in = append(in, "\x00\x00\x00secretxyz")
		// long
		in = append(in, strings.Repeat("z", 5000)+"secret")
		in = append(in, "AKIA"+strings.Repeat("Q", 16))
		// multibyte before match
		in = append(in, strings.Repeat("é", 100)+"secret")
		// boundary
		in = append(in, "x")
		in = append(in, "abababab")
		return in
	}
	inputs := mk()

	for _, p := range patterns {
		fre, err1 := gore2.Compile(p)
		sre, err2 := regexp.Compile(p)
		if err1 != nil || err2 != nil {
			continue
		}
		for _, s := range inputs {
			fm := fre.MatchString(s)
			sm := sre.MatchString(s)
			if fm != sm {
				t.Errorf("MATCH MISMATCH p=%q input=%q fork=%v stdlib=%v", p, trunc(s), fm, sm)
			}
			fi := fre.FindAllStringIndex(s, -1)
			si := sre.FindAllStringIndex(s, -1)
			if !eqIdx(fi, si) {
				t.Errorf("FINDALL MISMATCH p=%q input=%q\n fork=%v\n std =%v", p, trunc(s), fi, si)
			}
		}
	}
}

func trunc(s string) string {
	if len(s) > 40 {
		return fmt.Sprintf("%q...(len %d)", s[:40], len(s))
	}
	return fmt.Sprintf("%q", s)
}

func eqIdx(a, b [][]int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
