package auth

import (
	"crypto/sha256"
	"strings"
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

// ParseBearerToken parses an RFC 6750 Bearer authorization value. The scheme is
// case-insensitive; tokens must use the b64token alphabet and contain no spaces.
// Parsing does not validate the token's signature or grant authorization.
func ParseBearerToken(header string) (string, error) {
	// Bound before scanning, including an allowance for separator spaces.
	if len(header) > MaxTokenLen+16 {
		return "", ErrTokenTooLong
	}
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", ErrAuthInvalidBearerFormat
	}
	token = strings.TrimLeft(token, " ")
	if token == "" {
		return "", ErrAuthEmptyBearerToken
	}
	if len(token) > MaxTokenLen {
		return "", ErrTokenTooLong
	}
	padding := false
	for i, ch := range []byte(token) {
		if ch == '=' && i > 0 {
			padding = true
			continue
		}
		if padding || !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("-._~+/", rune(ch))) {
			return "", ErrAuthInvalidBearerFormat
		}
	}
	return token, nil
}
