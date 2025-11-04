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

// ValidatePHCHashFormat checks if a hash string has a valid and complete
// PHC format for Argon2id. It validates structure, parameters, and encoding,
// but does not verify a password against the hash.
func ValidatePHCHashFormat(phcHash string) error {
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 {
		return fmt.Errorf("%w: expected 6 parts, got %d", ErrPHCInvalidFormat, len(parts))
	}

	// Validate empty parts[0] (PHC format starts with $)
	if parts[0] != "" {
		return fmt.Errorf("%w: hash must start with $", ErrPHCInvalidFormat)
	}

	// Validate algorithm identifier
	if parts[1] != "argon2id" {
		return fmt.Errorf("%w: unsupported algorithm %q, expected argon2id", ErrPHCInvalidFormat, parts[1])
	}

	// Validate version
	var version int
	n, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || n != 1 {
		return fmt.Errorf("%w: invalid version format", ErrPHCInvalidFormat)
	}
	if version != argon2.Version {
		return fmt.Errorf("%w: unsupported version %d, expected %d", ErrPHCInvalidFormat, version, argon2.Version)
	}

	// Validate parameters
	var memory, time uint32
	var threads uint8
	n, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil || n != 3 {
		return fmt.Errorf("%w: failed to parse parameters", ErrPHCInvalidFormat)
	}

	// Validate parameter ranges
	if time == 0 || memory == 0 || threads == 0 {
		return fmt.Errorf("%w: parameters must be non-zero", ErrPHCInvalidFormat)
	}
	if memory > 4*1024*1024 { // 4GB limit
		return fmt.Errorf("%w: memory parameter exceeds maximum (4GB)", ErrPHCInvalidFormat)
	}
	if time > 1000 { // Reasonable upper bound
		return fmt.Errorf("%w: time parameter exceeds maximum (1000)", ErrPHCInvalidFormat)
	}
	if threads > 255 { // uint8 max, but practically much lower
		return fmt.Errorf("%w: threads parameter exceeds maximum (255)", ErrPHCInvalidFormat)
	}

	// Validate salt encoding
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPHCInvalidSalt, err)
	}
	if len(salt) < 8 { // Minimum safe salt length
		return fmt.Errorf("%w: salt too short (%d bytes)", ErrPHCInvalidSalt, len(salt))
	}

	// Validate hash encoding
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPHCInvalidHash, err)
	}
	if len(hash) < 16 { // Minimum hash length
		return fmt.Errorf("%w: hash too short (%d bytes)", ErrPHCInvalidHash, len(hash))
	}

	return nil
}