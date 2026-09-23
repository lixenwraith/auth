package auth

import (
	"crypto/sha256"
	"sync"
)

// SimpleTokenValidator is a concurrent in-memory allowlist of opaque tokens.
// Its zero value is ready to use. Tokens have no automatic expiration; use JWT
// for signed expiry or RemoveToken for explicit revocation.
type SimpleTokenValidator struct {
	tokens map[[32]byte]struct{} // keyed by SHA-256(token)
	mu     sync.RWMutex
}

// NewSimpleTokenValidator creates token validator
func NewSimpleTokenValidator() *SimpleTokenValidator {
	return &SimpleTokenValidator{
		tokens: make(map[[32]byte]struct{}),
	}
}

// ValidateToken checks if token is valid
func (v *SimpleTokenValidator) ValidateToken(token string) bool {
	if token == "" || len(token) > MaxTokenLen {
		return false
	}
	h := sha256.Sum256([]byte(token))
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.tokens[h]
	return ok
}

// AddToken adds a token to the allowlist. Empty and oversized tokens are ignored.
// Provision high-entropy tokens, e.g. with crypto/rand.Text; do not use passwords.
func (v *SimpleTokenValidator) AddToken(token string) {
	if token == "" || len(token) > MaxTokenLen {
		return
	}
	h := sha256.Sum256([]byte(token))
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.tokens == nil {
		v.tokens = make(map[[32]byte]struct{})
	}
	v.tokens[h] = struct{}{}
}

// RemoveToken removes token from validator
func (v *SimpleTokenValidator) RemoveToken(token string) {
	if token == "" || len(token) > MaxTokenLen {
		return
	}
	h := sha256.Sum256([]byte(token))
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.tokens, h)
}
