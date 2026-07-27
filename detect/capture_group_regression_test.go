package detect

import (
	"testing"

	"github.com/betterleaks/betterleaks/config"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	regexpre2 "github.com/betterleaks/betterleaks/regexp/re2"
	"github.com/betterleaks/betterleaks/sources"
)

// TestCaptureGroupContextSensitiveRegression locks in the historical
// secret-extraction behavior for capture groups whose value depends on match
// context. betterleaks extracts the capture group by re-running the rule regex
// on the (trimmed) full-match text via FindStringSubmatch, NOT by reading the
// in-context submatch offsets. For a context-sensitive pattern like \B(\d+),
// those two differ: on "a123 b456" the in-context group is "123"/"456", but
// re-running \B(\d+) on the isolated "123" matches at the internal non-boundary
// and yields "23"/"56".
//
// A performance change once switched to single-pass in-context offsets, which
// silently changed the reported secret. This test guards against reintroducing
// that behavior change.
func TestCaptureGroupContextSensitiveRegression(t *testing.T) {
	blregexp.SetEngine(regexpre2.RE2{})

	rule := config.Rule{
		RuleID:      "ctx-sensitive",
		Description: "context-sensitive capture group",
		Regex:       blregexp.MustCompile(`\B(\d+)`),
	}
	cfg := &config.Config{
		Rules:    map[string]config.Rule{"ctx-sensitive": rule},
		Keywords: map[string]struct{}{},
	}
	d := NewDetector(cfg)

	raw := "a123 b456"
	findings := d.detectFragmentWithRule(
		sources.Fragment{Raw: raw, Attributes: map[string]string{sources.AttrPath: "f.txt"}},
		raw, rule, nil, nil, &newlineCache{raw: raw},
	)

	got := make([]string, 0, len(findings))
	for _, f := range findings {
		got = append(got, f.Secret)
	}
	want := []string{"23", "56"}
	if len(got) != len(want) {
		t.Fatalf("got %d findings %v, want %v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("secret[%d]=%q, want %q (full got=%v). Capture-group extraction "+
				"must preserve FindStringSubmatch-on-secret semantics, not in-context offsets.", i, got[i], want[i], got)
		}
	}
}

// TestNoCaptureGroupRuleUnaffected confirms group-less rules (which now skip the
// per-match FindStringSubmatch entirely) still report the full match as secret.
func TestNoCaptureGroupRuleUnaffected(t *testing.T) {
	blregexp.SetEngine(regexpre2.RE2{})

	rule := config.Rule{
		RuleID:      "no-group",
		Description: "no capture group",
		Regex:       blregexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	}
	cfg := &config.Config{
		Rules:    map[string]config.Rule{"no-group": rule},
		Keywords: map[string]struct{}{},
	}
	d := NewDetector(cfg)

	raw := "key = AKIAIOSFODNN7EXAMPLE end"
	findings := d.detectFragmentWithRule(
		sources.Fragment{Raw: raw, Attributes: map[string]string{sources.AttrPath: "f.txt"}},
		raw, rule, nil, nil, &newlineCache{raw: raw},
	)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if want := "AKIAIOSFODNN7EXAMPLE"; findings[0].Secret != want {
		t.Fatalf("secret=%q, want %q", findings[0].Secret, want)
	}
}
