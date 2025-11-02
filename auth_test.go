// FILE: auth/auth_test.go
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthenticator(t *testing.T) {
	// Test HS256 creation
	auth, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err, "Failed to create HS256 authenticator")
	assert.Equal(t, "HS256", auth.algorithm)

	// Test with short secret
	_, err = NewAuthenticator([]byte("short"))
	assert.Equal(t, ErrSecretTooShort, err)

	// Test RS256 with private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	authRS, err := NewAuthenticator(privateKey, "RS256")
	require.NoError(t, err)
	assert.Equal(t, "RS256", authRS.algorithm)
	assert.NotNil(t, authRS.privateKey)
	assert.NotNil(t, authRS.publicKey)

	// Test RS256 with public key only
	authPub, err := NewAuthenticator(&privateKey.PublicKey, "RS256")
	require.NoError(t, err)
	assert.Equal(t, "RS256", authPub.algorithm)
	assert.Nil(t, authPub.privateKey)
	assert.NotNil(t, authPub.publicKey)

	// Test invalid algorithm
	_, err = NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"), "INVALID")
	assert.Equal(t, ErrInvalidAlgorithm, err)

	// Test invalid key type for HS256
	_, err = NewAuthenticator(privateKey, "HS256")
	assert.Equal(t, ErrInvalidKeyType, err)
}

func TestInterfaceCompliance(t *testing.T) {
	// Verify Authenticator implements AuthenticatorInterface
	auth, _ := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))

	var _ AuthenticatorInterface = auth

	// Test interface methods work
	hash, err := auth.HashPassword("testpass123")
	require.NoError(t, err)

	err = auth.VerifyPassword("testpass123", hash)
	assert.NoError(t, err)

	token, err := auth.GenerateToken("user1", nil)
	require.NoError(t, err)

	userID, _, err := auth.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "user1", userID)
}