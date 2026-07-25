package detect

import (
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	regexpre2 "github.com/betterleaks/betterleaks/regexp/re2"
	"github.com/betterleaks/betterleaks/sources"
)

// buildCorpus creates a realistic-ish scanning input: source-code-like lines,
// several real-looking secrets (so candidate findings are produced), and a big
// blob of base64 to exercise the decoder path.
func buildCorpus(nRepeat int) string {
	var sb strings.Builder
	block := `package main

import "fmt"

// config loading
func main() {
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	awsSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	ghToken := "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
	url := "https://user:hunter2password@example.com/path"
	fmt.Println(awsKey, awsSecret, ghToken, url)
	// some ordinary code with no secrets whatsoever, just words and numbers
	total := 0
	for i := 0; i < 100; i++ {
		total += i * 42
	}
	blob := "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyBmb3IgdGVzdGluZw=="
	_ = blob
}
`
	for i := 0; i < nRepeat; i++ {
		sb.WriteString(block)
	}
	return sb.String()
}

func newRE2Detector(tb testing.TB) *Detector {
	blregexp.SetEngine(regexpre2.RE2{})
	cfg, err := config.Default()
	if err != nil {
		tb.Fatalf("default config: %v", err)
	}
	return NewDetector(cfg)
}

// BenchmarkDetectCorpus scans a realistic multi-KB fragment with the full
// default ruleset using the re2 engine (production default).
func BenchmarkDetectCorpus(b *testing.B) {
	d := newRE2Detector(b)
	corpus := buildCorpus(40) // ~ tens of KB
	frag := sources.Fragment{Raw: corpus, Attributes: map[string]string{sources.AttrPath: "main.go"}}
	// warm up lazy regex compilation & filter programs
	_ = d.Detect(frag)
	b.ReportAllocs()
	b.SetBytes(int64(len(corpus)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(frag)
	}
}

// BenchmarkDetectCleanCorpus scans code with NO secrets (common case: most
// fragments have keyword hits but no regex matches).
func BenchmarkDetectCleanCorpus(b *testing.B) {
	d := newRE2Detector(b)
	clean := strings.Repeat("func doThing(a, b int) int { return a*b + 42 } // ordinary line of code\n", 400)
	frag := sources.Fragment{Raw: clean, Attributes: map[string]string{sources.AttrPath: "clean.go"}}
	_ = d.Detect(frag)
	b.ReportAllocs()
	b.SetBytes(int64(len(clean)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(frag)
	}
}

// BenchmarkDetectManyMatches builds a fragment with MANY matches of a single
// rule to stress the per-match FindStringSubmatch re-execution path.
func BenchmarkDetectManyMatches(b *testing.B) {
	d := newRE2Detector(b)
	var sb strings.Builder
	for i := 0; i < 300; i++ {
		sb.WriteString(`ghToken := "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"` + "\n")
	}
	frag := sources.Fragment{Raw: sb.String(), Attributes: map[string]string{sources.AttrPath: "many.go"}}
	_ = d.Detect(frag)
	b.ReportAllocs()
	b.SetBytes(int64(sb.Len()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(frag)
	}
}
