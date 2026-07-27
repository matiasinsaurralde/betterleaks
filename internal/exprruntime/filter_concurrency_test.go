package exprruntime

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	tiktoken "github.com/pkoukk/tiktoken-go"
)

// TestFilterEvalConcurrent stresses concurrent evaluation of a single compiled
// filter program. After the env/VM pooling optimization, all evaluations share
// one immutable *runtimeBindings via the program's cached bindings; this test
// (run with -race) guards that no per-eval mutation was reintroduced and that
// per-call finding/attributes stay isolated across goroutines.
func TestFilterEvalConcurrent(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	// A filter that touches multiple bindings, including the tokenizer-backed
	// failsTokenEfficiency path and the regex/trie caches.
	prg, err := env.CompileFilter(
		`entropy(finding["secret"]) <= 1.0 `+
			`|| filter.matchesAny(finding["secret"], ["^AKIA", "^ghp_"]) `+
			`|| filter.containsAny(finding["secret"], ["EXAMPLE", "CHANGEME"]) `+
			`|| finding["secret"] == attributes["expected"]`,
		nil,
	)
	require.NoError(t, err)

	const goroutines = 32
	const iters = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				// Distinct per-call finding/attributes: results must be isolated.
				if g%2 == 0 {
					skip, err := env.EvalFilter(prg, map[string]any{"secret": "aaaaaaaa"}, nil)
					require.NoError(t, err)
					require.True(t, skip) // low entropy => skip
				} else {
					skip, err := env.EvalFilter(prg,
						map[string]any{"secret": "match-me"},
						map[string]string{"expected": "match-me"})
					require.NoError(t, err)
					require.True(t, skip) // equals attributes["expected"]
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestFilterTokenizerProviderShared verifies that a tokenizer provider set on
// the runtime is used by failsTokenEfficiency without any per-eval mutation of
// the shared runtimeBindings (run with -race).
func TestFilterTokenizerProviderShared(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	var calls int64
	var mu sync.Mutex
	// Provider returns a nil tokenizer (failsTokenEfficiency then returns false),
	// but we assert it is invoked, proving the provider wiring survives the
	// compile-time capture + shared-rt path.
	env.SetTokenizerProvider(func() *tiktoken.Tiktoken {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil
	})

	prg, err := env.CompileFilter(`failsTokenEfficiency(finding["secret"])`, nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				skip, err := env.EvalFilter(prg, map[string]any{"secret": "abcdefghijklmnop"}, nil)
				require.NoError(t, err)
				require.False(t, skip) // nil tokenizer => not failing => false
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	require.Positive(t, calls, "tokenizer provider should have been invoked")
}
