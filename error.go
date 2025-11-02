// FILE: auth/errors.go
package auth

import (
	"errors"
	"fmt"
)

// Base authentication errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrWeakPassword       = errors.New("password must be at least 8 characters")
	ErrInvalidAlgorithm   = errors.New("invalid algorithm")
	ErrInvalidKeyType     = errors.New("invalid key type for algorithm")
)

// JWT-specific errors
var (
	ErrTokenMalformed         = errors.New("token: malformed structure")
	ErrTokenExpired           = errors.New("token: expired")
	ErrTokenNotYetValid       = errors.New("token: not yet valid")
	ErrTokenInvalidSignature  = errors.New("token: invalid signature")
	ErrTokenAlgorithmMismatch = errors.New("token: algorithm mismatch")
	ErrTokenMissingClaim      = errors.New("token: missing required claim")
	ErrTokenInvalidHeader     = errors.New("token: invalid header encoding")
	ErrTokenInvalidClaims     = errors.New("token: invalid claims encoding")
	ErrTokenInvalidJSON       = errors.New("token: malformed JSON")
	ErrTokenEmptyUserID       = errors.New("token: empty user ID")
	ErrTokenNoPrivateKey      = errors.New("token: private key required for signing")
	ErrTokenNoPublicKey       = errors.New("token: public key required for verification")
)

// JWT secret errors
var (
	ErrSecretTooShort = errors.New("JWT secret must be at least 32 bytes")
)

// RSA key parsing errors
var (
	ErrRSAInvalidPEM        = errors.New("rsa: failed to parse PEM block")
	ErrRSAInvalidPrivateKey = errors.New("rsa: invalid private key format")
	ErrRSAInvalidPublicKey  = errors.New("rsa: invalid public key format")
	ErrRSANotPublicKey      = errors.New("rsa: not an RSA public key")
)

// PHC format errors
var (
	ErrPHCInvalidFormat = errors.New("phc: invalid format")
	ErrPHCInvalidSalt   = errors.New("phc: invalid salt encoding")
	ErrPHCInvalidHash   = errors.New("phc: invalid hash encoding")
)

// SCRAM-specific errors
var (
	ErrSCRAMInvalidNonce     = errors.New("scram: invalid nonce or expired handshake")
	ErrSCRAMTimeout          = errors.New("scram: handshake timeout")
	ErrSCRAMVerifyInProgress = errors.New("scram: verification already in progress")
	ErrSCRAMInvalidProof     = errors.New("scram: invalid proof encoding")
	ErrSCRAMInvalidProofLen  = errors.New("scram: invalid proof length")
	ErrSCRAMServerAuthFailed = errors.New("scram: server authentication failed")
	ErrSCRAMInvalidState     = errors.New("scram: invalid handshake state")
	ErrSCRAMInvalidSalt      = errors.New("scram: invalid salt encoding")
	ErrSCRAMZeroParams       = errors.New("scram: invalid Argon2 parameters")
	ErrSCRAMSaltTooShort     = errors.New("scram: salt must be at least 16 bytes")
	ErrSCRAMNonceGenFailed   = errors.New("scram: failed to generate nonce")
)

// Credential import/export errors
var (
	ErrCredMissingUsername  = errors.New("credential: missing username")
	ErrCredMissingSalt      = errors.New("credential: missing salt")
	ErrCredInvalidSalt      = errors.New("credential: invalid salt encoding")
	ErrCredMissingTime      = errors.New("credential: missing argon_time")
	ErrCredMissingMemory    = errors.New("credential: missing argon_memory")
	ErrCredMissingThreads   = errors.New("credential: missing argon_threads")
	ErrCredMissingStoredKey = errors.New("credential: missing stored_key")
	ErrCredInvalidStoredKey = errors.New("credential: invalid stored_key encoding")
	ErrCredMissingServerKey = errors.New("credential: missing server_key")
	ErrCredInvalidServerKey = errors.New("credential: invalid server_key encoding")
	ErrCredInvalidType      = fmt.Errorf("credential: invalid type for field")
)

// HTTP auth parsing errors
var (
	ErrAuthInvalidBasicFormat   = errors.New("auth: invalid Basic auth format")
	ErrAuthInvalidBasicEncoding = errors.New("auth: invalid Basic auth base64 encoding")
	ErrAuthInvalidBasicCreds    = errors.New("auth: invalid Basic auth credentials format")
	ErrAuthInvalidBearerFormat  = errors.New("auth: invalid Bearer auth format")
	ErrAuthEmptyBearerToken     = errors.New("auth: empty Bearer token")
)

// Salt generation errors
var (
	ErrSaltGenerationFailed = errors.New("failed to generate salt")
)

// Key generation errors
var (
	ErrRSAKeyGenFailed = errors.New("failed to generate RSA key")
)