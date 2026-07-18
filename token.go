package auth

import (
	"crypto/sha256"
	"sync"
)

// SimpleTokenValidator implements in-memory token validation
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
	h := sha256.Sum256([]byte(token))
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.tokens[h]
	return ok
}

// AddToken adds token to validator
func (v *SimpleTokenValidator) AddToken(token string) {
	h := sha256.Sum256([]byte(token))
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tokens[h] = struct{}{}
}

// RemoveToken removes token from validator
func (v *SimpleTokenValidator) RemoveToken(token string) {
	h := sha256.Sum256([]byte(token))
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.tokens, h)
}
