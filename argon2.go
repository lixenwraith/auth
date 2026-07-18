package auth

import (
	"crypto/rand"
	"crypto/sha256"
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
	MaxPasswordLen      = 1024
	// upper bounds for untrusted PHC input
	MaxArgonSaltLen = 64
	MaxArgonKeyLen  = 64
	MaxPHCHashLen   = 256
)

// Execution budget for KDF parameters taken from an encoded record.
// parsePHC accepts the full PHC range (m <= 4 GiB, t <= 1000, p <= 255) because
// those values are well-formed; running them is a different decision. One
// crafted record would otherwise allocate 4 GiB. Applies to any Argon2 run
// whose parameters were chosen by a peer rather than by this process.
const (
	MaxVerifyArgonMemory  = 256 * 1024 // KiB
	MaxVerifyArgonTime    = 16
	MaxVerifyArgonThreads = 16
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
	if len(password) > MaxPasswordLen {
		return "", ErrPasswordTooLong
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
	rand.Read(salt) // cryptographically secure random bytes

	hash := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, params.keyLen)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.memory, params.time, params.threads, saltB64, hashB64), nil
}

// VerifyPassword checks password against PHC-format hash (standalone)
func VerifyPassword(password, phcHash string) error {
	_, err := verifyPHC(password, phcHash)
	return err
}

// MigrateFromPHC converts PHC hash to SCRAM credential
func MigrateFromPHC(username, password, phcHash string) (*Credential, error) {
	r, err := verifyPHC(password, phcHash)
	if err != nil {
		return nil, err
	}
	if len(r.derived) == DefaultArgonKeyLen {
		return credentialFromSaltedPassword(username, r.derived, r.salt, r.time, r.memory, r.threads), nil
	}
	// Non-standard digest length: derive at the required key length.
	return DeriveCredential(username, password, r.salt, r.time, r.memory, r.threads)
}

// key derivation split from the KDF so callers holding a salted
// password can build a credential without re-running Argon2.
func credentialFromSaltedPassword(username string, saltedPassword, salt []byte, time, memory uint32, threads uint8) *Credential {
	clientKey := computeHMAC(saltedPassword, []byte("Client Key"))
	serverKey := computeHMAC(saltedPassword, []byte("Server Key"))
	storedKey := sha256.Sum256(clientKey)

	return &Credential{
		Username:     username,
		Salt:         salt,
		ArgonTime:    time,
		ArgonMemory:  memory,
		ArgonThreads: threads,
		StoredKey:    storedKey[:],
		ServerKey:    serverKey,
	}
}

// ValidatePHCHashFormat checks if a hash string has a valid and complete
// PHC format for Argon2id. It validates structure, parameters, and encoding,
// but does not verify a password against the hash.
func ValidatePHCHashFormat(phcHash string) error {
	_, err := parsePHC(phcHash)
	return err
}

// parsed + verified PHC material, reused to avoid a second KDF pass
type phcResult struct {
	derived      []byte
	expectedHash []byte
	salt         []byte
	time         uint32
	memory       uint32
	threads      uint8
}

// verifyPHC validates format, bounds the password, runs the KDF once,
// and constant-time compares against the encoded digest.
func parsePHC(phcHash string) (*phcResult, error) {
	if len(phcHash) > MaxPHCHashLen {
		return nil, fmt.Errorf("%w: encoded hash exceeds %d bytes", ErrPHCInvalidFormat, MaxPHCHashLen)
	}

	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 {
		return nil, fmt.Errorf("%w: expected 6 parts, got %d", ErrPHCInvalidFormat, len(parts))
	}
	if parts[0] != "" {
		return nil, fmt.Errorf("%w: hash must start with $", ErrPHCInvalidFormat)
	}
	if parts[1] != "argon2id" {
		return nil, fmt.Errorf("%w: unsupported algorithm %q, expected argon2id", ErrPHCInvalidFormat, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || parts[2] != fmt.Sprintf("v=%d", version) {
		return nil, fmt.Errorf("%w: invalid version format", ErrPHCInvalidFormat)
	}
	if version != argon2.Version {
		return nil, fmt.Errorf("%w: unsupported version %d, expected %d", ErrPHCInvalidFormat, version, argon2.Version)
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil || parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", memory, time, threads) {
		return nil, fmt.Errorf("%w: failed to parse parameters", ErrPHCInvalidFormat)
	}

	if time == 0 || memory == 0 || threads == 0 {
		return nil, fmt.Errorf("%w: parameters must be non-zero", ErrPHCInvalidFormat)
	}
	if memory > 4*1024*1024 {
		return nil, fmt.Errorf("%w: memory parameter exceeds maximum (4GB)", ErrPHCInvalidFormat)
	}
	if time > 1000 {
		return nil, fmt.Errorf("%w: time parameter exceeds maximum (1000)", ErrPHCInvalidFormat)
	}
	if threads > 255 {
		return nil, fmt.Errorf("%w: threads parameter exceeds maximum (255)", ErrPHCInvalidFormat)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPHCInvalidSalt, err)
	}
	if len(salt) < 8 {
		return nil, fmt.Errorf("%w: salt too short (%d bytes)", ErrPHCInvalidSalt, len(salt))
	}
	if len(salt) > MaxArgonSaltLen {
		return nil, fmt.Errorf("%w: salt too long (%d bytes)", ErrPHCInvalidSalt, len(salt))
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPHCInvalidHash, err)
	}
	if len(hash) < 16 {
		return nil, fmt.Errorf("%w: hash too short (%d bytes)", ErrPHCInvalidHash, len(hash))
	}
	if len(hash) > MaxArgonKeyLen {
		return nil, fmt.Errorf("%w: hash too long (%d bytes)", ErrPHCInvalidHash, len(hash))
	}

	return &phcResult{
		expectedHash: hash,
		salt:         salt,
		time:         time,
		memory:       memory,
		threads:      threads,
	}, nil
}

// verifyPHC validates format, bounds the password, runs the KDF once, and
// constant-time compares against the encoded digest.
func verifyPHC(password, phcHash string) (*phcResult, error) {
	if len(password) > MaxPasswordLen {
		return nil, ErrPasswordTooLong
	}

	r, err := parsePHC(phcHash)
	if err != nil {
		return nil, err
	}

	// Bound the KDF before it runs; the record is untrusted input
	if err := checkArgonCost(r.memory, r.time, r.threads); err != nil {
		return nil, err
	}

	r.derived = argon2.IDKey([]byte(password), r.salt, r.time, r.memory, r.threads, uint32(len(r.expectedHash)))
	if subtle.ConstantTimeCompare(r.derived, r.expectedHash) != 1 {
		return nil, ErrInvalidCredentials
	}
	return r, nil
}

func checkArgonCost(memory, time uint32, threads uint8) error {
	switch {
	case memory > MaxVerifyArgonMemory:
		return fmt.Errorf("%w: memory %d KiB exceeds %d", ErrPHCCostTooHigh, memory, MaxVerifyArgonMemory)
	case time > MaxVerifyArgonTime:
		return fmt.Errorf("%w: time %d exceeds %d", ErrPHCCostTooHigh, time, MaxVerifyArgonTime)
	case threads > MaxVerifyArgonThreads:
		return fmt.Errorf("%w: threads %d exceeds %d", ErrPHCCostTooHigh, threads, MaxVerifyArgonThreads)
	}
	return nil
}
