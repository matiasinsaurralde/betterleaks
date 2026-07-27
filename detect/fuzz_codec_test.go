package detect

import (
	"testing"

	"github.com/betterleaks/betterleaks/config"
	blregexp "github.com/betterleaks/betterleaks/regexp"
)

func permissiveDetector() *Detector {
	// A no-keyword rule that matches runs of printable ASCII. This reliably
	// produces matches inside decoded base64/hex/percent/unicode blobs so the
	// AdjustMatchIndex / CurrentLine offset-mapping code is exercised.
	rule := config.Rule{
		RuleID: "any-printable",
		Regex:  blregexp.MustCompile(`[\x21-\x7e]{5,}`),
	}
	cfg := &config.Config{
		Rules:          map[string]config.Rule{"any-printable": rule},
		Keywords:       map[string]struct{}{},
		KeywordToRules: map[string][]string{},
		NoKeywordRules: []string{"any-printable"},
		OrderedRules:   []string{"any-printable"},
	}
	d := NewDetector(cfg)
	d.MaxDecodeDepth = 5
	return d
}

func FuzzDecodePanic(f *testing.F) {
	seeds := []string{
		"aws_secret=%41%42%43%44%45",
		"U+0041U+0042U+0043U+0044U+0045 token=abc",
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"YWFhYWFhYWFhYWFhYWFhYWFh",
		"%2541%2542%2543%2544%2545",
		`ABCDE`,
		"aaaa%41%42%43%44%45bbbb deadbeefdeadbeefdeadbeefdeadbeef",
		"U+0041 %41%42%43 deadbeefdeadbeefdeadbeefdeadbeefdead",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	d := permissiveDetector()

	f.Fuzz(func(t *testing.T, content string) {
		_ = d.DetectString(content)
	})
}
