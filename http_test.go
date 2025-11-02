// FILE: auth/http_test.go
package auth

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPAuthParsing(t *testing.T) {
	// Test Basic Auth
	basicHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	username, password, err := ParseBasicAuth(basicHeader)
	require.NoError(t, err)
	assert.Equal(t, "user", username)
	assert.Equal(t, "pass", password)

	// Test Bearer Token
	bearerHeader := "Bearer test-token-xyz"
	token, err := ParseBearerToken(bearerHeader)
	require.NoError(t, err)
	assert.Equal(t, "test-token-xyz", token)

	// Test ExtractAuthType
	assert.Equal(t, "Basic", ExtractAuthType(basicHeader))
	assert.Equal(t, "Bearer", ExtractAuthType(bearerHeader))
	assert.Equal(t, "Custom", ExtractAuthType("Custom somedata"))
	assert.Equal(t, "", ExtractAuthType("InvalidHeader"))

	// Test invalid formats
	_, _, err = ParseBasicAuth("Invalid header")
	assert.Error(t, err)
	assert.Equal(t, ErrAuthInvalidBasicFormat, err)

	_, err = ParseBearerToken("Invalid header")
	assert.Error(t, err)
	assert.Equal(t, ErrAuthInvalidBearerFormat, err)

	// Test malformed Basic auth
	_, _, err = ParseBasicAuth("Basic not-base64!")
	assert.Error(t, err)
	assert.Equal(t, ErrAuthInvalidBasicEncoding, err)

	_, _, err = ParseBasicAuth("Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon")))
	assert.Error(t, err)
	assert.Equal(t, ErrAuthInvalidBasicCreds, err)

	// Test empty Bearer token
	_, err = ParseBearerToken("Bearer ")
	assert.Error(t, err)
	assert.Equal(t, ErrAuthEmptyBearerToken, err)
}