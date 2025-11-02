// FILE: auth/jwt.go
package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// GenerateToken creates a JWT token with user claims
func (a *Authenticator) GenerateToken(userID string, claims map[string]any) (string, error) {
	if userID == "" {
		return "", ErrTokenEmptyUserID
	}

	if a.algorithm == "RS256" && a.privateKey == nil {
		return "", ErrTokenNoPrivateKey
	}

	// Build JWT claims
	now := time.Now()
	jwtClaims := map[string]any{
		"sub": userID,
		"iat": now.Unix(),
		"exp": now.Add(7 * 24 * time.Hour).Unix(), // 7 days expiry
	}

	// Reserved claims that cannot be overridden
	reservedClaims := map[string]bool{
		"sub": true, "iat": true, "exp": true, "nbf": true,
		"iss": true, "aud": true, "jti": true, "typ": true,
		"alg": true,
	}

	// Merge custom claims
	for k, v := range claims {
		if !reservedClaims[k] {
			jwtClaims[k] = v
		}
	}

	// Create JWT header
	header := map[string]any{
		"alg": a.algorithm,
		"typ": "JWT",
	}

	// Encode header and payload
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(jwtClaims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create signature
	signingInput := headerB64 + "." + claimsB64
	var signature string

	switch a.algorithm {
	case "HS256":
		h := hmac.New(sha256.New, a.jwtSecret)
		h.Write([]byte(signingInput))
		signature = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	case "RS256":
		hashed := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, a.privateKey, crypto.SHA256, hashed[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign token: %w", err)
		}
		signature = base64.RawURLEncoding.EncodeToString(sig)
	}

	// Combine to form JWT
	token := signingInput + "." + signature

	return token, nil
}

// ValidateToken verifies JWT and returns userID and claims
func (a *Authenticator) ValidateToken(token string) (string, map[string]any, error) {
	// Split token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, ErrTokenMalformed
	}

	// Decode header to check algorithm
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, ErrTokenInvalidHeader
	}

	var header map[string]any
	if err = json.Unmarshal(headerJSON, &header); err != nil {
		return "", nil, ErrTokenInvalidJSON
	}

	// Verify algorithm matches
	if alg, ok := header["alg"].(string); !ok || alg != a.algorithm {
		return "", nil, ErrTokenAlgorithmMismatch
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]

	switch a.algorithm {
	case "HS256":
		h := hmac.New(sha256.New, a.jwtSecret)
		h.Write([]byte(signingInput))
		expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

		if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
			return "", nil, ErrTokenInvalidSignature
		}

	case "RS256":
		if a.publicKey == nil {
			return "", nil, ErrTokenNoPublicKey
		}

		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return "", nil, ErrTokenInvalidSignature
		}

		hashed := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(a.publicKey, crypto.SHA256, hashed[:], sig); err != nil {
			return "", nil, ErrTokenInvalidSignature
		}
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, ErrTokenInvalidClaims
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", nil, ErrTokenInvalidJSON
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return "", nil, ErrTokenExpired
		}
	}

	// Check not before
	if nbf, ok := claims["nbf"].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return "", nil, ErrTokenNotYetValid
		}
	}

	// Extract userID
	userID, ok := claims["sub"].(string)
	if !ok {
		return "", nil, ErrTokenMissingClaim
	}

	return userID, claims, nil
}

// parseRSAPrivateKey parses PEM encoded RSA private key
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

// parseRSAPublicKey parses PEM encoded RSA public key
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