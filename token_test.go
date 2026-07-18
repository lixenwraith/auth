package auth

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestSimpleTokenValidator(t *testing.T) {
	v := NewSimpleTokenValidator()
	const first, second = "test-token-123", "test-token-456"

	isTrue(t, !v.ValidateToken(first), "empty validator rejects")

	v.AddToken(first)
	v.AddToken(second)
	isTrue(t, v.ValidateToken(first), "first token")
	isTrue(t, v.ValidateToken(second), "second token")
	isTrue(t, !v.ValidateToken("invalid-token"), "unknown token")

	// matching is exact
	isTrue(t, !v.ValidateToken(first+"x"), "suffix")
	isTrue(t, !v.ValidateToken(first[:len(first)-1]), "prefix")
	isTrue(t, !v.ValidateToken(strings.ToUpper(first)), "case")
	isTrue(t, !v.ValidateToken(" "+first), "leading space")

	v.RemoveToken(first)
	isTrue(t, !v.ValidateToken(first), "removed token")
	isTrue(t, v.ValidateToken(second), "surviving token")

	// removing an absent token is a no-op
	v.RemoveToken("never-added")
	eq(t, len(v.tokens), 1, "entry count after no-op removal")

	// repeated adds are idempotent
	v.AddToken(second)
	v.AddToken(second)
	eq(t, len(v.tokens), 1, "entry count after duplicate adds")

	// the empty token is storable and matches only itself
	v.AddToken("")
	isTrue(t, v.ValidateToken(""), "empty token accepted once added")
	v.RemoveToken("")
	isTrue(t, !v.ValidateToken(""), "empty token removed")
}

func TestSimpleTokenValidatorKeying(t *testing.T) {
	v := NewSimpleTokenValidator()
	tokens := []string{
		"", "a", "a\x00b", "a\x00c", "🔑", strings.Repeat("a", 1<<16),
	}
	for _, tok := range tokens {
		v.AddToken(tok)
	}
	eq(t, len(v.tokens), len(tokens), "distinct entries")

	for i, tok := range tokens {
		isTrue(t, v.ValidateToken(tok), fmt.Sprintf("token %d", i))
	}
	for i, tok := range tokens {
		v.RemoveToken(tok)
		isTrue(t, !v.ValidateToken(tok), fmt.Sprintf("token %d removed", i))
	}
	eq(t, len(v.tokens), 0, "empty after removal")
}

func TestSimpleTokenValidatorConcurrent(t *testing.T) {
	v := NewSimpleTokenValidator()
	const n = 256

	// pre-populate half the space so readers see hits and misses
	for i := n / 2; i < n; i++ {
		v.AddToken(fmt.Sprintf("token-%d", i))
	}

	// each goroutine owns one token, so the final state is deterministic
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token := fmt.Sprintf("token-%d", i)
			v.AddToken(token)
			v.ValidateToken(token)
			v.ValidateToken(fmt.Sprintf("absent-%d", i))
			if i%2 == 0 {
				v.RemoveToken(token)
			}
		}()
	}
	wg.Wait()

	for i := range n {
		eq(t, v.ValidateToken(fmt.Sprintf("token-%d", i)), i%2 != 0, fmt.Sprintf("token %d", i))
	}
	eq(t, len(v.tokens), n/2, "surviving entries")
}
