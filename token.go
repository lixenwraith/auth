// FILE: auth/token.go
package auth

import (
	"crypto/subtle"
	"sync"
)

// SimpleTokenValidator implements in-memory token validation
type SimpleTokenValidator struct {
	tokens map[string]struct{}
	mu     sync.RWMutex
}

// NewSimpleTokenValidator creates token validator
func NewSimpleTokenValidator() *SimpleTokenValidator {
	return &SimpleTokenValidator{
		tokens: make(map[string]struct{}),
	}
}

// ValidateToken checks if token is valid
func (v *SimpleTokenValidator) ValidateToken(token string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Constant-time comparison for each stored token
	for storedToken := range v.tokens {
		if subtle.ConstantTimeEq(int32(len(token)), int32(len(storedToken))) == 1 {
			if subtle.ConstantTimeCompare([]byte(token), []byte(storedToken)) == 1 {
				return true
			}
		}
	}
	return false
}

// AddToken adds token to validator
func (v *SimpleTokenValidator) AddToken(token string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tokens[token] = struct{}{}
}

// RemoveToken removes token from validator
func (v *SimpleTokenValidator) RemoveToken(token string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.tokens, token)
}