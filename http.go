package auth

import (
	"encoding/base64"
	"strings"
)

// ParseBasicAuth extracts username/password from Basic auth header
func ParseBasicAuth(header string) (username, password string, err error) {
	encoded, ok := strings.CutPrefix(header, "Basic ")
	if !ok {
		return "", "", ErrAuthInvalidBasicFormat
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", ErrAuthInvalidBasicEncoding
	}

	username, password, ok = strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", ErrAuthInvalidBasicCreds
	}

	return username, password, nil
}

// ParseBearerToken extracts token from Bearer auth header
func ParseBearerToken(header string) (token string, err error) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return "", ErrAuthInvalidBearerFormat
	}
	if token == "" {
		return "", ErrAuthEmptyBearerToken
	}

	return token, nil
}

// ExtractAuthType returns authentication type from header
func ExtractAuthType(header string) string {
	if authType, _, ok := strings.Cut(header, " "); ok {
		return authType
	}
	return "" // Matches original behavior if no space is found or string is empty
}
