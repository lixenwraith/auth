// FILE: auth/argon2.go
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Default Argon2id parameters
const (
	DefaultArgonTime    = 3         // iterations (reduce for faster but less secure auth)
	DefaultArgonMemory  = 64 * 1024 // 64 MB
	DefaultArgonThreads = 4
	DefaultArgonSaltLen = 16
	DefaultArgonKeyLen  = 32
)

// HashPassword creates an Argon2id PHC-format hash
func (a *Authenticator) HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", ErrWeakPassword
	}

	// Generate salt
	salt := make([]byte, DefaultArgonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("%w: %v", ErrSaltGenerationFailed, err)
	}

	// Derive key using Argon2id
	hash := argon2.IDKey([]byte(password), salt, a.argonTime, a.argonMemory, a.argonThreads, DefaultArgonKeyLen)

	// Construct PHC format
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	phcHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, a.argonMemory, a.argonTime, a.argonThreads, saltB64, hashB64)

	return phcHash, nil
}

// VerifyPassword checks password against PHC-format hash
func (a *Authenticator) VerifyPassword(password, phcHash string) error {
	// Parse PHC format
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrPHCInvalidFormat
	}

	var memory, time uint32
	var threads uint8
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPHCInvalidSalt, err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPHCInvalidHash, err)
	}

	// Compute hash with same parameters
	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))

	// Constant-time comparison
	if subtle.ConstantTimeCompare(computedHash, expectedHash) != 1 {
		return ErrInvalidCredentials
	}

	return nil
}

// MigrateFromPHC converts existing Argon2 PHC hash to SCRAM credential
func MigrateFromPHC(username, password, phcHash string) (*Credential, error) {
	// Parse PHC format
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, ErrPHCInvalidFormat
	}

	var memory, time uint32
	var threads uint8
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, ErrPHCInvalidSalt
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, ErrPHCInvalidHash
	}

	// Verify password against hash
	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))
	if subtle.ConstantTimeCompare(computedHash, expectedHash) != 1 {
		return nil, ErrInvalidCredentials
	}

	// Derive SCRAM credential with same parameters
	return DeriveCredential(username, password, salt, time, memory, threads)
}