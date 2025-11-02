// FILE: auth/http.go
package auth

import (
	"encoding/base64"
	"strings"
)

// ParseBasicAuth extracts username/password from Basic auth header
func ParseBasicAuth(header string) (username, password string, err error) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", ErrAuthInvalidBasicFormat
	}

	encoded := strings.TrimPrefix(header, prefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", ErrAuthInvalidBasicEncoding
	}

	credentials := string(decoded)
	idx := strings.IndexByte(credentials, ':')
	if idx < 0 {
		return "", "", ErrAuthInvalidBasicCreds
	}

	return credentials[:idx], credentials[idx+1:], nil
}

// ParseBearerToken extracts token from Bearer auth header
func ParseBearerToken(header string) (token string, err error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", ErrAuthInvalidBearerFormat
	}

	token = strings.TrimPrefix(header, prefix)
	if token == "" {
		return "", ErrAuthEmptyBearerToken
	}

	return token, nil
}

// ExtractAuthType returns authentication type from header
func ExtractAuthType(header string) string {
	if strings.HasPrefix(header, "Basic ") {
		return "Basic"
	}
	if strings.HasPrefix(header, "Bearer ") {
		return "Bearer"
	}

	// Extract first word as auth type
	idx := strings.IndexByte(header, ' ')
	if idx > 0 {
		return header[:idx]
	}
	return ""
}