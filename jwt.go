package auth

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWT configuration defaults
const (
	DefaultTokenLifetime = 24 * time.Hour
	DefaultLeeway        = 5 * time.Minute
	MaxTokenLen          = 16 * 1024
	MinRSABits           = 2048
)

// customClaims extends RegisteredClaims with arbitrary user data
type customClaims struct {
	jwt.RegisteredClaims
	Extra map[string]any `json:"extra,omitempty"`
}

// JWT manages token generation and validation. Construct once and reuse; its
// immutable configuration and parser are safe for concurrent use.
type JWT struct {
	parser        *jwt.Parser
	algorithm     jwt.SigningMethod
	signKey       any // []byte for HMAC, *rsa.PrivateKey for RSA
	verifyKey     any // []byte for HMAC, *rsa.PublicKey for RSA
	tokenLifetime time.Duration
	leeway        time.Duration
	issuer        string
	audience      []string
}

// JWTOption configures JWT behavior at construction time. Do not apply options
// to an existing manager.
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
		j.audience = append([]string(nil), aud...)
	}
}

// NewJWT creates JWT manager for HS256 (symmetric)
func NewJWT(secret []byte, opts ...JWTOption) (*JWT, error) {
	if len(secret) < 32 {
		return nil, ErrSecretTooShort
	}

	secret = bytes.Clone(secret)
	j := &JWT{
		algorithm:     jwt.SigningMethodHS256,
		signKey:       secret,
		verifyKey:     secret,
		tokenLifetime: DefaultTokenLifetime,
		leeway:        DefaultLeeway,
	}

	j.configure(opts)
	return j, nil
}

// NewJWTRSA creates JWT manager for RS256 (asymmetric)
func NewJWTRSA(privateKey *rsa.PrivateKey, opts ...JWTOption) (*JWT, error) {
	if privateKey == nil {
		return nil, ErrTokenNoPrivateKey
	}

	privateKey, err := cloneRSAPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	j := &JWT{
		algorithm:     jwt.SigningMethodRS256,
		signKey:       privateKey,
		verifyKey:     &privateKey.PublicKey,
		tokenLifetime: DefaultTokenLifetime,
		leeway:        DefaultLeeway,
	}

	j.configure(opts)
	return j, nil
}

// NewJWTRSAFromPEM creates a JWT manager for RS256 from raw PEM-encoded private key data.
func NewJWTRSAFromPEM(privateKeyPEM []byte, opts ...JWTOption) (*JWT, error) {
	privateKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	// Call the original constructor with the now-parsed key
	return NewJWTRSA(privateKey, opts...)
}

// NewJWTVerifier creates JWT manager for verification only (RS256)
func NewJWTVerifier(publicKey *rsa.PublicKey, opts ...JWTOption) (*JWT, error) {
	if publicKey == nil {
		return nil, ErrTokenNoPublicKey
	}

	if err := validateRSAPublicKey(publicKey); err != nil {
		return nil, err
	}
	publicKey = &rsa.PublicKey{N: new(big.Int).Set(publicKey.N), E: publicKey.E}
	j := &JWT{
		algorithm:     jwt.SigningMethodRS256,
		signKey:       nil, // Cannot sign
		verifyKey:     publicKey,
		tokenLifetime: DefaultTokenLifetime,
		leeway:        DefaultLeeway,
	}

	j.configure(opts)
	return j, nil
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

	signed, err := token.SignedString(j.signKey)
	if len(signed) > MaxTokenLen {
		return "", ErrTokenTooLong
	}
	return signed, err
}

func (j *JWT) configure(opts []JWTOption) {
	for _, opt := range opts {
		if opt != nil {
			opt(j)
		}
	}
	j.parser = jwt.NewParser(
		jwt.WithLeeway(j.leeway), jwt.WithAudience(j.audience...), jwt.WithIssuer(j.issuer),
		jwt.WithValidMethods([]string{j.algorithm.Alg()}), jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(), jwt.WithStrictDecoding(),
	)
}

// ValidateToken verifies JWT and returns a nonempty subject plus application
// claims. Issuer/audience are enforced when configured; claims are nil on error.
func (j *JWT) ValidateToken(tokenString string) (string, map[string]any, error) {
	return validateJWT(j.parser, j.verifyKey, tokenString)
}

func validateJWT(parser *jwt.Parser, key any, tokenString string) (string, map[string]any, error) {
	if len(tokenString) > MaxTokenLen {
		return "", nil, ErrTokenTooLong
	}
	if strings.ContainsAny(tokenString, "\r\n") {
		return "", nil, ErrTokenMalformed
	}
	token, err := parser.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Header["crit"]; ok {
			return nil, ErrTokenMalformed
		}
		return key, nil
	})
	if err != nil {
		return "", nil, mapJWTError(err)
	}
	claims, ok := token.Claims.(*customClaims)
	if !ok || !token.Valid {
		return "", nil, ErrTokenMalformed
	}
	if claims.Subject == "" {
		return "", nil, ErrTokenEmptyUserID
	}
	return claims.Subject, claims.Extra, nil
}

// mapJWTError translates jwt library errors to auth package errors
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return fmt.Errorf("%w: %w", ErrTokenMalformed, err)
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return fmt.Errorf("%w: %w", ErrTokenMalformed, err)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return fmt.Errorf("%w: %w", ErrTokenInvalidSignature, err)
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w: %w", ErrTokenExpired, err)
	case errors.Is(err, jwt.ErrTokenNotValidYet), errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return fmt.Errorf("%w: %w", ErrTokenNotYetValid, err)
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return fmt.Errorf("%w: %w", ErrTokenMissingClaim, err)
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return fmt.Errorf("%w: %w", ErrTokenMissingClaim, err)
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return fmt.Errorf("%w: %w", ErrTokenMissingClaim, err)
	default:
		return fmt.Errorf("%w: %w", ErrTokenMalformed, err)
	}
}

// GenerateHS256Token creates HS256 JWT without manager instance
func GenerateHS256Token(secret []byte, userID string, claims map[string]any, lifetime time.Duration) (string, error) {
	if len(secret) < 32 {
		return "", ErrSecretTooShort
	}
	if userID == "" {
		return "", ErrTokenEmptyUserID
	}

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
		},
		Extra: claims,
	})

	signed, err := token.SignedString(secret)
	if len(signed) > MaxTokenLen {
		return "", ErrTokenTooLong
	}
	return signed, err
}

// ValidateHS256Token is the legacy unscoped HS256 adapter. It requires exp/sub
// and validates iat/nbf with DefaultLeeway, but does not constrain issuer/audience.
// Prefer a reusable JWT with explicit issuer/audience for new services.
func ValidateHS256Token(secret []byte, tokenString string) (string, map[string]any, error) {
	if len(secret) < 32 {
		return "", nil, ErrSecretTooShort
	}

	return validateJWT(standaloneHS256Parser, secret, tokenString)
}

var standaloneHS256Parser = jwt.NewParser(
	jwt.WithValidMethods([]string{"HS256"}), jwt.WithLeeway(DefaultLeeway),
	jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithStrictDecoding(),
)

func validateRSAPublicKey(key *rsa.PublicKey) error {
	if key.N == nil || key.N.Sign() <= 0 || key.N.Bit(0) == 0 || key.E < 3 || key.E&1 == 0 || key.E > 1<<31-1 {
		return ErrRSAInvalidPublicKey
	}
	if key.N.BitLen() < MinRSABits {
		return ErrRSAWeakKey
	}
	return nil
}

func cloneRSAPrivateKey(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if err := validateRSAPublicKey(&key.PublicKey); err != nil {
		return nil, err
	}
	if key.D == nil || key.D.Sign() <= 0 || len(key.Primes) < 2 {
		return nil, ErrRSAInvalidPrivateKey
	}
	copy := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E},
		D:         new(big.Int).Set(key.D), Primes: make([]*big.Int, len(key.Primes)),
	}
	for i, prime := range key.Primes {
		if prime == nil || prime.Sign() <= 0 {
			return nil, ErrRSAInvalidPrivateKey
		}
		copy.Primes[i] = new(big.Int).Set(prime)
	}
	if err := copy.Validate(); err != nil {
		return nil, ErrRSAInvalidPrivateKey
	}
	copy.Precompute()
	return copy, nil
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrRSAInvalidPEM
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// PKCS8 fallback
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrRSAInvalidPrivateKey
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
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
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
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
