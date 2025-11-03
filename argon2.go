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
	DefaultArgonTime    = 3         // iterations
	DefaultArgonMemory  = 64 * 1024 // 64 MB
	DefaultArgonThreads = 4
	DefaultArgonSaltLen = 16
	DefaultArgonKeyLen  = 32
)

// argonParams holds configurable Argon2id parameters
type argonParams struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	saltLen uint32
}

// Option configures Argon2id hashing parameters
type Option func(*argonParams)

// WithTime sets Argon2 iterations
func WithTime(t uint32) Option {
	return func(p *argonParams) {
		if t > 0 {
			p.time = t
		}
	}
}

// WithMemory sets Argon2 memory in KiB
func WithMemory(m uint32) Option {
	return func(p *argonParams) {
		if m > 0 {
			p.memory = m
		}
	}
}

// WithThreads sets Argon2 parallelism
func WithThreads(t uint8) Option {
	return func(p *argonParams) {
		if t > 0 {
			p.threads = t
		}
	}
}

// HashPassword creates Argon2id PHC-format hash (standalone)
func HashPassword(password string, opts ...Option) (string, error) {
	if len(password) < 8 {
		return "", ErrWeakPassword
	}

	params := &argonParams{
		time:    DefaultArgonTime,
		memory:  DefaultArgonMemory,
		threads: DefaultArgonThreads,
		keyLen:  DefaultArgonKeyLen,
		saltLen: DefaultArgonSaltLen,
	}

	for _, opt := range opts {
		opt(params)
	}

	salt := make([]byte, params.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("%w: %v", ErrSaltGenerationFailed, err)
	}

	hash := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, params.keyLen)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.memory, params.time, params.threads, saltB64, hashB64), nil
}

// VerifyPassword checks password against PHC-format hash (standalone)
func VerifyPassword(password, phcHash string) error {
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

	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))

	if subtle.ConstantTimeCompare(computedHash, expectedHash) != 1 {
		return ErrInvalidCredentials
	}

	return nil
}

// MigrateFromPHC converts PHC hash to SCRAM credential
func MigrateFromPHC(username, password, phcHash string) (*Credential, error) {
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

	// Use standalone function for verification
	if err := VerifyPassword(password, phcHash); err != nil {
		return nil, err
	}

	return DeriveCredential(username, password, salt, time, memory, threads)
}