// FILE: auth/token_test.go
package auth

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleTokenValidator(t *testing.T) {
	validator := NewSimpleTokenValidator()

	token1 := "test-token-123"
	token2 := "test-token-456"

	// Add tokens
	validator.AddToken(token1)
	validator.AddToken(token2)

	// Validate existing tokens
	assert.True(t, validator.ValidateToken(token1))
	assert.True(t, validator.ValidateToken(token2))

	// Invalid token
	assert.False(t, validator.ValidateToken("invalid-token"))

	// Remove token
	validator.RemoveToken(token1)
	assert.False(t, validator.ValidateToken(token1))
	assert.True(t, validator.ValidateToken(token2))
}

func TestConcurrentTokenValidator(t *testing.T) {
	validator := NewSimpleTokenValidator()

	// Add tokens concurrently
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := fmt.Sprintf("token-%d", idx)
			validator.AddToken(token)
		}(i)
	}
	wg.Wait()

	// Validate concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := fmt.Sprintf("token-%d", idx)
			assert.True(t, validator.ValidateToken(token))
		}(i)
	}
	wg.Wait()

	// Remove concurrently
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := fmt.Sprintf("token-%d", idx)
			validator.RemoveToken(token)
		}(i)
	}
	wg.Wait()

	// Verify removal
	for i := 0; i < 50; i++ {
		token := fmt.Sprintf("token-%d", i)
		assert.False(t, validator.ValidateToken(token))
	}
	for i := 50; i < 100; i++ {
		token := fmt.Sprintf("token-%d", i)
		assert.True(t, validator.ValidateToken(token))
	}
}