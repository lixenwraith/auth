// FILE: auth/auth.go
package auth

import (
	"crypto/rsa"
	"fmt"
)

// Authenticator provides password hashing and JWT operations
type Authenticator struct {
	algorithm    string
	jwtSecret    []byte          // For HS256
	privateKey   *rsa.PrivateKey // For RS256
	publicKey    *rsa.PublicKey  // For RS256
	argonTime    uint32
	argonMemory  uint32
	argonThreads uint8
}

// NewAuthenticator creates a new authenticator with specified algorithm
func NewAuthenticator(key any, algorithm ...string) (*Authenticator, error) {
	alg := "HS256"
	if len(algorithm) > 0 && algorithm[0] != "" {
		alg = algorithm[0]
	}

	auth := &Authenticator{
		algorithm:    alg,
		argonTime:    DefaultArgonTime,
		argonMemory:  DefaultArgonMemory,
		argonThreads: DefaultArgonThreads,
	}

	switch alg {
	case "HS256":
		secret, ok := key.([]byte)
		if !ok {
			return nil, ErrInvalidKeyType
		}
		if len(secret) < 32 {
			return nil, ErrSecretTooShort
		}
		auth.jwtSecret = secret

	case "RS256":
		switch k := key.(type) {
		case *rsa.PrivateKey:
			auth.privateKey = k
			auth.publicKey = &k.PublicKey
		case *rsa.PublicKey:
			auth.publicKey = k
		case []byte:
			// Try parsing as PEM
			if privKey, err := parseRSAPrivateKey(k); err == nil {
				auth.privateKey = privKey
				auth.publicKey = &privKey.PublicKey
			} else if pubKey, err := parseRSAPublicKey(k); err == nil {
				auth.publicKey = pubKey
			} else {
				return nil, fmt.Errorf("failed to parse RSA key: %w", err)
			}
		default:
			return nil, ErrInvalidKeyType
		}

	default:
		return nil, ErrInvalidAlgorithm
	}

	return auth, nil
}