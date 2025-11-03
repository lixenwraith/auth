// FILE: auth/jwt.go
package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWT configuration defaults
const (
	DefaultTokenLifetime = 24 * time.Hour
	DefaultLeeway        = 5 * time.Minute
)

// customClaims extends RegisteredClaims with arbitrary user data
type customClaims struct {
	jwt.RegisteredClaims
	Extra map[string]any `json:"extra,omitempty"`
}

// JWT manages token generation and validation
type JWT struct {
	algorithm     jwt.SigningMethod
	signKey       any // []byte for HMAC, *rsa.PrivateKey for RSA
	verifyKey     any // []byte for HMAC, *rsa.PublicKey for RSA
	tokenLifetime time.Duration
	leeway        time.Duration
	issuer        string
	audience      []string
}

// JWTOption configures JWT behavior
type JWTOption func(*JWT)

// WithTokenLifetime sets token expiration duration
func WithTokenLifetime(d time.Duration) JWTOption {
	return func(j *JWT) {
		if d > 0 {
			j.tokenLifetime = d
		}
	}
}

// WithLeeway sets clock skew tolerance
func WithLeeway(d time.Duration) JWTOption {
	return func(j *JWT) {
		if d >= 0 {
			j.leeway = d
		}
	}
}

// WithIssuer sets token issuer claim
func WithIssuer(iss string) JWTOption {
	return func(j *JWT) {
		j.issuer = iss
	}
}

// WithAudience sets token audience claim
func WithAudience(aud []string) JWTOption {
	return func(j *JWT) {
		j.audience = aud
	}
}

// NewJWT creates JWT manager for HS256 (symmetric)
func NewJWT(secret []byte, opts ...JWTOption) (*JWT, error) {
	if len(secret) < 32 {
		return nil, ErrSecretTooShort
	}

	j := &JWT{
		algorithm:     jwt.SigningMethodHS256,
		signKey:       secret,
		verifyKey:     secret,
		tokenLifetime: DefaultTokenLifetime,
		leeway:        DefaultLeeway,
	}

	for _, opt := range opts {
		opt(j)
	}

	return j, nil
}

// NewJWTRSA creates JWT manager for RS256 (asymmetric)
func NewJWTRSA(privateKey *rsa.PrivateKey, opts ...JWTOption) (*JWT, error) {
	if privateKey == nil {
		return nil, ErrTokenNoPrivateKey
	}

	j := &JWT{
		algorithm:     jwt.SigningMethodRS256,
		signKey:       privateKey,
		verifyKey:     &privateKey.PublicKey,
		tokenLifetime: DefaultTokenLifetime,
		leeway:        DefaultLeeway,
	}

	for _, opt := range opts {
		opt(j)
	}

	return j, nil
}

// NewJWTVerifier creates JWT manager for verification only (RS256)
func NewJWTVerifier(publicKey *rsa.PublicKey, opts ...JWTOption) (*JWT, error) {
	if publicKey == nil {
		return nil, ErrTokenNoPublicKey
	}

	j := &JWT{
		algorithm:     jwt.SigningMethodRS256,
		signKey:       nil, // Cannot sign
		verifyKey:     publicKey,
		tokenLifetime: DefaultTokenLifetime,
		leeway:        DefaultLeeway,
	}

	for _, opt := range opts {
		opt(j)
	}

	return j, nil
}

// GenerateToken creates signed JWT with claims
func (j *JWT) GenerateToken(userID string, claims map[string]any) (string, error) {
	if userID == "" {
		return "", ErrTokenEmptyUserID
	}

	if j.signKey == nil {
		return "", ErrTokenNoPrivateKey
	}

	now := time.Now()
	registeredClaims := jwt.RegisteredClaims{
		Subject:   userID,
		Issuer:    j.issuer,
		Audience:  j.audience,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(j.tokenLifetime)),
		NotBefore: jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(j.algorithm, customClaims{
		RegisteredClaims: registeredClaims,
		Extra:            claims,
	})

	return token.SignedString(j.signKey)
}

// ValidateToken verifies JWT and extracts claims
func (j *JWT) ValidateToken(tokenString string) (string, map[string]any, error) {
	parser := jwt.NewParser(
		jwt.WithLeeway(j.leeway),
		jwt.WithAudience(j.audience...),
		jwt.WithIssuer(j.issuer),
		jwt.WithValidMethods([]string{j.algorithm.Alg()}),
		jwt.WithExpirationRequired(),
	)

	token, err := parser.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (any, error) {
		// Algorithm already validated by WithValidMethods
		return j.verifyKey, nil
	})

	if err != nil {
		return "", nil, mapJWTError(err)
	}

	claims, ok := token.Claims.(*customClaims)
	if !ok || !token.Valid {
		return "", nil, ErrTokenMalformed
	}

	return claims.Subject, claims.Extra, nil
}

// mapJWTError translates jwt library errors to auth package errors
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return fmt.Errorf("%w : %w", ErrTokenMalformed, err)
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return fmt.Errorf("%w : %w", ErrTokenMalformed, err)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return fmt.Errorf("%w : %w", ErrTokenInvalidSignature, err)
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w : %w", ErrTokenExpired, err)
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return fmt.Errorf("%w : %w", ErrTokenNotYetValid, err)
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return fmt.Errorf("%w : %w", ErrTokenMissingClaim, err)
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return fmt.Errorf("%w : %w", ErrTokenMissingClaim, err)
	default:
		// Check for algorithm mismatch in error message
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return fmt.Errorf("%w : %w", ErrTokenAlgorithmMismatch, err)
		}
		return fmt.Errorf("%w : %w", ErrTokenMalformed, err)
	}
}

// Standalone helper functions for one-off operations

// GenerateHS256Token creates HS256 JWT without manager instance
func GenerateHS256Token(secret []byte, userID string, claims map[string]any, lifetime time.Duration) (string, error) {
	if len(secret) < 32 {
		return "", ErrSecretTooShort
	}

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
		},
		Extra: claims,
	})

	return token.SignedString(secret)
}

// ValidateHS256Token verifies HS256 JWT without manager instance
func ValidateHS256Token(secret []byte, tokenString string) (string, map[string]any, error) {
	if len(secret) < 32 {
		return "", nil, ErrSecretTooShort
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithLeeway(DefaultLeeway),
	)

	token, err := parser.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (any, error) {
		return secret, nil
	})

	if err != nil {
		return "", nil, mapJWTError(err)
	}

	claims, ok := token.Claims.(*customClaims)
	if !ok || !token.Valid {
		return "", nil, ErrTokenMalformed
	}

	return claims.Subject, claims.Extra, nil
}

// RSA Utilities

// NewJWTRSAFromPEM creates a JWT manager for RS256 from raw PEM-encoded private key data.
func NewJWTRSAFromPEM(privateKeyPEM []byte, opts ...JWTOption) (*JWT, error) {
	privateKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	// Call the original constructor with the now-parsed key
	return NewJWTRSA(privateKey, opts...)
}

// NewJWTVerifierFromPEM creates a JWT manager for verification from raw PEM-encoded public key data.
func NewJWTVerifierFromPEM(publicKeyPEM []byte, opts ...JWTOption) (*JWT, error) {
	publicKey, err := parseRSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	// Call the original constructor with the now-parsed key
	return NewJWTVerifier(publicKey, opts...)
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrRSAInvalidPEM
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrRSAInvalidPrivateKey
	}
	return key, nil
}

// parseRSAPublicKey parses a PEM-encoded RSA public key.
func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrRSAInvalidPEM
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrRSAInvalidPublicKey
	}
	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, ErrRSANotPublicKey
	}
	return pubKey, nil
}