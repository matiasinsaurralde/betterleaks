package detect

import (
	// "encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// samePath reports whether two file paths refer to the same location, tolerating
// OS separator differences. The file source normalizes fragment paths to forward
// slashes (filepath.ToSlash), whereas config/baseline paths keep the native
// separator, so a raw == comparison misses on Windows and the config or baseline
// file ends up being scanned against itself.
func samePath(a, b string) bool {
	return filepath.ToSlash(filepath.Clean(a)) == filepath.ToSlash(filepath.Clean(b))
}

var linkCleaner = strings.NewReplacer(
	" ", "%20",
	"%", "%25",
)

func createScmLink(platform, remoteURL string, finding report.Finding) string {
	p, _ := scm.PlatformFromString(platform)
	commitSha := finding.Attr(sources.AttrGitSHA)
	path := finding.Attr(sources.AttrPath)
	if p == scm.UnknownPlatform || p == scm.NoPlatform || commitSha == "" || path == "" {
		return ""
	}

	// Clean the path.
	filePath, _, hasInnerPath := strings.Cut(path, sources.InnerPathSeparator)
	filePath = linkCleaner.Replace(filePath)

	switch p {
	case scm.GitHubPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?plain=1"
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-L%d", finding.EndLine)
		}
		return link
	case scm.GitLabPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-%d", finding.EndLine)
		}
		return link
	case scm.AzureDevOpsPlatform:
		link := fmt.Sprintf("%s/commit/%s?path=/%s", remoteURL, commitSha, filePath)
		// Add line information if applicable
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("&line=%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("&lineEnd=%d", finding.EndLine)
		}
		// This is a bit dirty, but Azure DevOps does not highlight the line when the lineStartColumn and lineEndColumn are not provided
		link += "&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files"
		return link
	case scm.GiteaPlatform:
		link := fmt.Sprintf("%s/src/commit/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?display=source"
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-L%d", finding.EndLine)
		}
		return link
	case scm.BitbucketPlatform:
		link := fmt.Sprintf("%s/src/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#lines-%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf(":%d", finding.EndLine)
		}
		return link
	default:
		// This should never happen.
		return ""
	}
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
// Another way to think about what this is doing is calculating the number of bits
// needed to on average encode the data. So, the higher the entropy, the more random the data, the
// more bits needed to encode that data.
func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	// Count ASCII runes (the overwhelming majority of secrets) in a stack array
	// to avoid a map allocation on this per-finding hot path; fall back to a map
	// only for the rare non-ASCII rune. The divisor stays len(data) (byte count)
	// to preserve the exact values the previous map-based implementation produced.
	var ascii [128]int
	var wide map[rune]int
	for _, char := range data {
		if char < 128 {
			ascii[char]++
		} else {
			if wide == nil {
				wide = make(map[rune]int)
			}
			wide[char]++
		}
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range ascii {
		if count == 0 {
			continue
		}
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}
	for _, count := range wide {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// filter will dedupe and redact findings
func filter(findings []report.Finding) []report.Finding {
	// Collect every required finding's (line, secret) so we can suppress
	// standalone duplicates that are already surfaced as components.
	requiredSet := make(map[string]struct{})
	for _, f := range findings {
		for _, set := range f.RequiredSets {
			for _, comp := range set.Components {
				requiredSet[fmt.Sprintf("%d:%s", comp.StartLine, comp.Secret)] = struct{}{}
			}
		}
	}

	var retFindings []report.Finding
	for _, f := range findings {
		include := true

		// Skip findings that are already surfaced as a required component
		// of another (composite) finding in this batch.
		if _, isRequired := requiredSet[fmt.Sprintf("%d:%s", f.StartLine, f.Secret)]; isRequired {
			redactedMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
			logging.Trace().Msgf("skipping %s finding (%s), already a required component of another finding", f.RuleID, redactedMatch)
			include = false
		} else if isSuppressedByHigherSpecificityFinding(f, findings) {
			include = false
		}

		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func isSuppressedByHigherSpecificityFinding(f report.Finding, findings []report.Finding) bool {
	for _, fPrime := range findings {
		if f.StartLine == fPrime.StartLine &&
			f.Attributes[sources.AttrGitSHA] == fPrime.Attributes[sources.AttrGitSHA] &&
			f.RuleID != fPrime.RuleID &&
			strings.Contains(fPrime.Secret, f.Secret) &&
			fPrime.RuleSpecificity > f.RuleSpecificity {
			genericMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
			betterMatch := strings.ReplaceAll(fPrime.Match, fPrime.Secret, "REDACTED")
			logging.Debug().Msgf("skipping %s finding (%s), %s rule takes precedence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
			return true
		}
		for _, set := range fPrime.RequiredSets {
			for _, comp := range set.Components {
				if f.StartLine == comp.StartLine &&
					f.RuleID != comp.RuleID &&
					strings.Contains(comp.Secret, f.Secret) &&
					comp.RuleSpecificity > f.RuleSpecificity {
					genericMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
					betterMatch := strings.ReplaceAll(comp.Match, comp.Secret, "REDACTED")
					logging.Trace().Msgf("skipping %s finding (%s), %s required component takes precedence (%s)", f.RuleID, genericMatch, comp.RuleID, betterMatch)
					return true
				}
			}
		}
	}
	return false
}

func printFinding(f report.Finding, noColor bool, redact uint, legacyPrint bool) {
	if legacyPrint {
		f.PrintLegacy(noColor, redact)
		return
	}
	f.Print(noColor, redact)
}

// stripEmptyMeta removes keys whose value is an empty string or nil.
func stripEmptyMeta(m map[string]any) map[string]any {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if v == nil {
			continue
		}
		out[k] = v
	}
	return out
}

// findNewlineIndices returns the byte offsets of all newlines in s.
// This replaces the previous regex-based approach which was expensive
// when using go-re2 (WASM overhead for a literal \n search).
//
// The result is a flat []int of newline offsets. Callers previously received
// [][]int{{idx, idx+1}, ...} but only ever used the first element (the newline
// offset), so a flat slice avoids one heap allocation per line.
func findNewlineIndices(s string) []int {
	indices := make([]int, 0, strings.Count(s, "\n"))
	offset := 0
	for {
		i := strings.IndexByte(s[offset:], '\n')
		if i == -1 {
			break
		}
		idx := offset + i
		indices = append(indices, idx)
		offset = idx + 1
	}
	return indices
}

// submatchStrings converts capture-group offsets returned by
// FindAllStringSubmatchIndex into the []string form returned by
// FindStringSubmatch: index 0 is the full match and index i is capture group i.
// A non-participating group (offset -1) becomes "".
func submatchStrings(s string, m []int) []string {
	groups := make([]string, len(m)/2)
	for i := range groups {
		start, end := m[2*i], m[2*i+1]
		if start >= 0 && end >= start {
			groups[i] = s[start:end]
		}
	}
	return groups
}

// containsAllowSignature checks if the line contains any of the allow signatures
func containsAllowSignature(line string) bool {
	for _, sig := range allowSignatures {
		if strings.Contains(line, sig) {
			return true
		}
	}
	return false
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func RedactFindings(findings []report.Finding, percent uint) {
	if percent == 0 {
		return
	}
	for i := range findings {
		findings[i].Redact(percent)
	}
}
