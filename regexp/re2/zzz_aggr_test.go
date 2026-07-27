package re2

import (
	"regexp"
	"strings"
	"sync"
	"testing"

	gore2 "github.com/betterleaks/go-re2"
)

// Aggressive: many goroutines, large inputs forcing wasm memory growth,
// capture groups, correctness compared to stdlib per-result.
func TestAggressiveCorrectness(t *testing.T) {
	type pc struct {
		p        string
		fre      *gore2.Regexp
		sre      *regexp.Regexp
	}
	pats := []string{
		`(\w+)=(\w+)`,
		`key\s*[:=]\s*"([A-Za-z0-9+/=]{5,})"`,
		`(?i)(aws|gcp|azure)_(secret|key)_([a-z0-9]{4,})`,
		`([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})`,
	}
	var pcs []pc
	for _, p := range pats {
		f, e1 := gore2.Compile(p)
		s, e2 := regexp.Compile(p)
		if e1 != nil || e2 != nil {
			continue
		}
		pcs = append(pcs, pc{p, f, s})
	}

	big := strings.Repeat("aws_secret_deadbeef abc=123 1.22.33.44 key: \"AAAAbbbbCCCC\"\n", 20000) // ~1.1MB, forces growth
	inputs := []string{
		"a=b c=d",
		"key = \"AAAAbbbbCCCC\"",
		"aws_secret_cafebabe",
		"10.0.0.1 255.255.255.255",
		big,
		strings.Repeat("é", 3000) + " x=y",
		string([]byte{0x00, 0xff}) + "k=v" + string([]byte{0x00}),
	}

	var wg sync.WaitGroup
	fail := make(chan string, 64)
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for it := 0; it < 60; it++ {
				c := pcs[(seed+it)%len(pcs)]
				s := inputs[(seed*3+it)%len(inputs)]
				fi := c.fre.FindAllStringIndex(s, -1)
				si := c.sre.FindAllStringIndex(s, -1)
				if !eqIdx(fi, si) {
					select {
					case fail <- "FINDALL mismatch p=" + c.p + " len=" + itoa(len(s)):
					default:
					}
					return
				}
				// submatch correctness
				fsm := c.fre.FindStringSubmatch(s)
				ssm := c.sre.FindStringSubmatch(s)
				if !eqStr(fsm, ssm) {
					select {
					case fail <- "SUBMATCH mismatch p=" + c.p + " len=" + itoa(len(s)):
					default:
					}
					return
				}
				// replace correctness
				fr := c.fre.ReplaceAllString(s, "[$1]")
				sr := c.sre.ReplaceAllString(s, "[$1]")
				if fr != sr {
					select {
					case fail <- "REPLACE mismatch p=" + c.p + " len=" + itoa(len(s)):
					default:
					}
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(fail)
	for m := range fail {
		t.Error(m)
	}
}

func eqStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
