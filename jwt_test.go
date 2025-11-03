// FILE: auth/jwt_test.go
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTHS256(t *testing.T) {
	secret := []byte("test-secret-key-must-be-32-bytes")
	jwtMgr, err := NewJWT(secret)
	require.NoError(t, err)

	userID := "user123"
	claims := map[string]any{
		"email": "test@example.com",
		"role":  "admin",
	}

	// Generate token
	token, err := jwtMgr.GenerateToken(userID, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate token
	extractedUserID, extractedClaims, err := jwtMgr.ValidateToken(token)
	require.NoError(t, err)

	assert.Equal(t, userID, extractedUserID)
	assert.Equal(t, "test@example.com", extractedClaims["email"])
	assert.Equal(t, "admin", extractedClaims["role"])
}

func TestJWTRS256(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Test with private key (can sign and verify)
	jwtMgr, err := NewJWTRSA(privateKey)
	require.NoError(t, err)

	userID := "user456"
	claims := map[string]any{
		"scope": "read:all",
	}

	// Generate token
	token, err := jwtMgr.GenerateToken(userID, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate with same manager
	extractedUserID, extractedClaims, err := jwtMgr.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, extractedUserID)
	assert.Equal(t, "read:all", extractedClaims["scope"])

	// Test with verifier only (public key)
	verifier, err := NewJWTVerifier(&privateKey.PublicKey)
	require.NoError(t, err)

	// Should validate token
	extractedUserID, _, err = verifier.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, extractedUserID)

	// Should not generate token
	_, err = verifier.GenerateToken(userID, claims)
	assert.Equal(t, ErrTokenNoPrivateKey, err)
}

func TestJWTOptions(t *testing.T) {
	secret := []byte("test-secret-key-must-be-32-bytes")

	// Test custom lifetime
	jwtMgr, err := NewJWT(secret,
		WithTokenLifetime(1*time.Hour),
		WithIssuer("test-issuer"),
		WithAudience([]string{"api.example.com"}),
	)
	require.NoError(t, err)

	token, err := jwtMgr.GenerateToken("user1", nil)
	require.NoError(t, err)

	// Parse token to check claims
	parsed, _ := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return secret, nil
	})

	claims := parsed.Claims.(jwt.MapClaims)

	// Check issuer
	assert.Equal(t, "test-issuer", claims["iss"])

	// Check audience
	aud := claims["aud"].([]any)
	assert.Contains(t, aud, "api.example.com")

	// Check expiration is ~1 hour
	exp := int64(claims["exp"].(float64))
	iat := int64(claims["iat"].(float64))
	assert.InDelta(t, 3600, exp-iat, 10)
}

func TestJWTErrors(t *testing.T) {
	secret := []byte("test-secret-key-must-be-32-bytes")
	jwtMgr, err := NewJWT(secret)
	require.NoError(t, err)

	// Empty user ID
	_, err = jwtMgr.GenerateToken("", nil)
	assert.Equal(t, ErrTokenEmptyUserID, err)

	// Invalid token format
	_, _, err = jwtMgr.ValidateToken("invalid.token")
	assert.ErrorIs(t, err, ErrTokenMalformed)

	// Tampered signature
	token, _ := jwtMgr.GenerateToken("user1", nil)
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + parts[1] + ".invalidsignature"
	_, _, err = jwtMgr.ValidateToken(tampered)
	assert.ErrorIs(t, err, ErrTokenInvalidSignature)

	// Wrong algorithm
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaMgr, _ := NewJWTRSA(rsaKey)
	rsaToken, _ := rsaMgr.GenerateToken("user1", nil)

	_, _, err = jwtMgr.ValidateToken(rsaToken)
	assert.ErrorIs(t, err, ErrTokenInvalidSignature)
}

func TestJWTExpiration(t *testing.T) {
	secret := []byte("test-secret-key-must-be-32-bytes")

	// Create token with 1 second lifetime
	jwtMgr, err := NewJWT(secret, WithTokenLifetime(1*time.Second), WithLeeway(0))
	require.NoError(t, err)

	token, err := jwtMgr.GenerateToken("user1", nil)
	require.NoError(t, err)

	// Should be valid immediately
	_, _, err = jwtMgr.ValidateToken(token)
	assert.NoError(t, err)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Should be expired
	_, _, err = jwtMgr.ValidateToken(token)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestLeeway(t *testing.T) {
	secret := []byte("test-secret-key-must-be-32-bytes")

	// Create manager with no leeway
	jwtMgr, err := NewJWT(secret, WithLeeway(0))
	require.NoError(t, err)

	// Manually create a token with NotBefore in future
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user1",
		"nbf": now.Add(2 * time.Second).Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(secret)
	require.NoError(t, err)

	// Should fail immediately (not valid yet)
	_, _, err = jwtMgr.ValidateToken(tokenString)
	assert.ErrorIs(t, err, ErrTokenNotYetValid)

	// Create manager with leeway
	jwtMgrWithLeeway, err := NewJWT(secret, WithLeeway(5*time.Second))
	require.NoError(t, err)

	// Should pass with leeway
	_, _, err = jwtMgrWithLeeway.ValidateToken(tokenString)
	assert.NoError(t, err)
}

func TestStandaloneFunctions(t *testing.T) {
	secret := []byte("test-secret-key-must-be-32-bytes")
	userID := "standalone-user"
	claims := map[string]any{"test": "value"}

	// Generate token
	token, err := GenerateHS256Token(secret, userID, claims, 1*time.Hour)
	require.NoError(t, err)

	// Validate token
	extractedUserID, extractedClaims, err := ValidateHS256Token(secret, token)
	require.NoError(t, err)

	assert.Equal(t, userID, extractedUserID)
	assert.Equal(t, "value", extractedClaims["test"])

	// Test with short secret
	_, err = GenerateHS256Token([]byte("short"), userID, claims, 1*time.Hour)
	assert.Equal(t, ErrSecretTooShort, err)
}

func TestJWTRSAFromPEM(t *testing.T) {
	// 1. Generate a new RSA key pair for this test
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// 2. Encode the private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 3. Encode the public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// 4. Test the PEM constructor for the signer
	jwtMgr, err := NewJWTRSAFromPEM(privateKeyPEM)
	require.NoError(t, err)

	token, err := jwtMgr.GenerateToken("user-from-pem", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// 5. Test the PEM constructor for the verifier
	verifier, err := NewJWTVerifierFromPEM(publicKeyPEM)
	require.NoError(t, err)

	userID, _, err := verifier.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "user-from-pem", userID)

	// 6. Test failure cases with invalid data
	_, err = NewJWTRSAFromPEM([]byte("invalid pem data"))
	assert.ErrorIs(t, err, ErrRSAInvalidPEM)

	_, err = NewJWTVerifierFromPEM([]byte("invalid pem data"))
	assert.ErrorIs(t, err, ErrRSAInvalidPEM)
}