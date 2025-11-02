// FILE: auth/jwt_test.go
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTHS256(t *testing.T) {
	auth, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err)

	userID := "user123"
	claims := map[string]any{
		"email": "test@example.com",
		"role":  "admin",
	}

	// Generate token
	token, err := auth.GenerateToken(userID, claims)
	require.NoError(t, err, "Failed to generate token")
	assert.NotEmpty(t, token)

	// Validate token
	extractedUserID, extractedClaims, err := auth.ValidateToken(token)
	require.NoError(t, err, "Failed to validate token")

	assert.Equal(t, userID, extractedUserID)
	assert.Equal(t, "test@example.com", extractedClaims["email"])
	assert.Equal(t, "admin", extractedClaims["role"])

	// Test invalid token
	_, _, err = auth.ValidateToken("invalid.token.here")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenInvalidJSON))

	// Test tampered token
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "JWT should have 3 parts")

	tampered := parts[0] + "." + parts[1] + ".invalidsignature"
	_, _, err = auth.ValidateToken(tampered)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenInvalidSignature))

	// Test reserved claims cannot be overridden
	overrideClaims := map[string]any{
		"sub": "override",
		"iat": 12345,
		"exp": 67890,
		"nbf": 11111,
		"iss": "attacker",
		"aud": "victim",
		"jti": "fake",
	}

	token, err = auth.GenerateToken(userID, overrideClaims)
	require.NoError(t, err)

	extractedUserID, extractedClaims, err = auth.ValidateToken(token)
	require.NoError(t, err)

	assert.Equal(t, userID, extractedUserID, "UserID should not be overridden")
	assert.NotEqual(t, 12345, extractedClaims["iat"], "iat should not be overridden")
	assert.NotEqual(t, 67890, extractedClaims["exp"], "exp should not be overridden")
	assert.NotContains(t, extractedClaims, "nbf", "nbf should not be added from user claims")
	assert.NotContains(t, extractedClaims, "iss", "iss should not be added from user claims")
}

func TestJWTRS256(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Test with private key (can sign and verify)
	authPriv, err := NewAuthenticator(privateKey, "RS256")
	require.NoError(t, err)

	userID := "user456"
	claims := map[string]any{
		"email": "rs256@example.com",
		"scope": "read:all",
	}

	// Generate token
	token, err := authPriv.GenerateToken(userID, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate token with private key auth (has public key too)
	extractedUserID, extractedClaims, err := authPriv.ValidateToken(token)
	require.NoError(t, err)

	assert.Equal(t, userID, extractedUserID)
	assert.Equal(t, "rs256@example.com", extractedClaims["email"])
	assert.Equal(t, "read:all", extractedClaims["scope"])

	// Test with public key only (can only verify)
	authPub, err := NewAuthenticator(&privateKey.PublicKey, "RS256")
	require.NoError(t, err)

	// Should be able to validate token
	extractedUserID, extractedClaims, err = authPub.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, extractedUserID)

	// Should not be able to generate token
	_, err = authPub.GenerateToken(userID, claims)
	assert.Error(t, err, "Public key only auth should not generate tokens")
	assert.Equal(t, ErrTokenNoPrivateKey, err)

	// Test algorithm mismatch
	authHS256, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err)

	_, _, err = authHS256.ValidateToken(token)
	assert.Error(t, err, "HS256 auth should not validate RS256 token")
	// assert.True(t, errors.Is(err, ErrInvalidToken))
	assert.True(t, errors.Is(err, ErrTokenAlgorithmMismatch))

	fmt.Println(err)
}

func TestExpiredToken(t *testing.T) {
	auth, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err)

	userID := "user123"

	// Generate normal token (should have 7 days expiry)
	token, err := auth.GenerateToken(userID, nil)
	require.NoError(t, err)

	_, extractedClaims, err := auth.ValidateToken(token)
	require.NoError(t, err)

	// Check expiry is in future (approximately 7 days)
	expiry := extractedClaims["exp"].(float64)
	now := time.Now().Unix()

	assert.Greater(t, expiry, float64(now), "Token expiry should be in future")
	assert.InDelta(t, expiry, float64(now+7*24*60*60), 10,
		"Token expiry should be approximately 7 days from now")
}

func TestCorruptJWTParts(t *testing.T) {
	auth, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err)

	// Test with missing parts
	_, _, err = auth.ValidateToken("only.two")
	assert.True(t, errors.Is(err, ErrTokenMalformed))

	// Test with invalid header encoding
	_, _, err = auth.ValidateToken("not-base64!.valid.valid")
	assert.Error(t, err)

	// Test with invalid claims encoding
	validHeader := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	_, _, err = auth.ValidateToken(validHeader + ".not-base64!.valid")
	assert.Error(t, err)

	// Test with invalid JSON in claims
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{invalid json"))
	_, _, err = auth.ValidateToken(validHeader + "." + invalidJSON + ".signature")
	assert.Error(t, err)
}