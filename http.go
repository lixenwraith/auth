package auth

import "strings"

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
