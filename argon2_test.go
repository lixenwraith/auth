// FILE: auth/argon2_test.go
package auth

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordHashing(t *testing.T) {
	password := "testPassword123"

	// Test hashing with default parameters
	hash, err := HashPassword(password)
	require.NoError(t, err, "Failed to hash password")

	// Verify PHC format
	assert.True(t, strings.HasPrefix(hash, "$argon2id$"),
		"Hash should have argon2id prefix, got: %s", hash)

	// Test verification with correct password
	err = VerifyPassword(password, hash)
	assert.NoError(t, err, "Failed to verify correct password")

	// Test verification with incorrect password
	err = VerifyPassword("wrongPassword", hash)
	assert.Error(t, err, "Verification should fail for incorrect password")
	assert.Equal(t, ErrInvalidCredentials, err)

	// Test weak password
	_, err = HashPassword("weak")
	assert.Equal(t, ErrWeakPassword, err, "Should reject weak password")

	// Test with custom options
	hash, err = HashPassword(password,
		WithTime(5),
		WithMemory(128*1024),
		WithThreads(8))
	require.NoError(t, err)

	err = VerifyPassword(password, hash)
	assert.NoError(t, err)

	// Test malformed PHC hash
	err = VerifyPassword(password, "$invalid$format")
	assert.Error(t, err, "Should reject malformed hash")

	// Test corrupted salt
	corruptedHash := strings.Replace(hash, "$argon2id$", "$argon2id$", 1)
	parts := strings.Split(corruptedHash, "$")
	if len(parts) == 6 {
		parts[4] = "invalid!base64"
		corruptedHash = strings.Join(parts, "$")
		err = VerifyPassword(password, corruptedHash)
		assert.Error(t, err, "Should reject corrupted salt")
	}
}

func TestEmptyPasswordAfterValidation(t *testing.T) {
	// Empty password should be rejected by length check
	_, err := HashPassword("")
	assert.Equal(t, ErrWeakPassword, err)

	// 8-character password should pass
	hash, err := HashPassword("12345678")
	require.NoError(t, err)

	err = VerifyPassword("12345678", hash)
	assert.NoError(t, err)
}

func TestConcurrentPasswordOperations(t *testing.T) {
	password := "testPassword123"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	// Test concurrent verification
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := VerifyPassword(password, hash)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

func TestPHCMigration(t *testing.T) {
	password := "testPassword123"
	username := "migrationUser"

	// Generate PHC hash
	phcHash, err := HashPassword(password)
	require.NoError(t, err)

	// Migrate to SCRAM credential
	cred, err := MigrateFromPHC(username, password, phcHash)
	require.NoError(t, err)
	assert.Equal(t, username, cred.Username)
	assert.NotNil(t, cred.StoredKey)
	assert.NotNil(t, cred.ServerKey)

	// Test with wrong password
	_, err = MigrateFromPHC(username, "wrongPassword", phcHash)
	assert.Equal(t, ErrInvalidCredentials, err)

	// Test with invalid PHC format
	_, err = MigrateFromPHC(username, password, "$invalid$format")
	assert.Error(t, err)
}

func TestValidatePHCHashFormat(t *testing.T) {
	// Generate valid hash for testing
	validHash, err := HashPassword("testPassword123")
	require.NoError(t, err)

	// Test valid hash
	err = ValidatePHCHashFormat(validHash)
	assert.NoError(t, err, "Valid hash should pass validation")

	// Test malformed formats
	testCases := []struct {
		name    string
		hash    string
		wantErr error
	}{
		{"empty", "", ErrPHCInvalidFormat},
		{"not PHC format", "plaintext", ErrPHCInvalidFormat},
		{"wrong prefix", "argon2id$v=19$m=65536,t=3,p=4$salt$hash", ErrPHCInvalidFormat},
		{"wrong algorithm", "$bcrypt$v=19$m=65536,t=3,p=4$salt$hash", ErrPHCInvalidFormat},
		{"missing version", "$argon2id$$m=65536,t=3,p=4$salt$hash", ErrPHCInvalidFormat},
		{"wrong version", "$argon2id$v=1$m=65536,t=3,p=4$salt$hash", ErrPHCInvalidFormat},
		{"missing params", "$argon2id$v=19$$salt$hash", ErrPHCInvalidFormat},
		{"invalid params format", "$argon2id$v=19$invalid$salt$hash", ErrPHCInvalidFormat},
		{"zero time", "$argon2id$v=19$m=65536,t=0,p=4$salt$hash", ErrPHCInvalidFormat},
		{"zero memory", "$argon2id$v=19$m=0,t=3,p=4$salt$hash", ErrPHCInvalidFormat},
		{"zero threads", "$argon2id$v=19$m=65536,t=3,p=0$salt$hash", ErrPHCInvalidFormat},
		{"excessive memory", "$argon2id$v=19$m=5000000,t=3,p=4$salt$hash", ErrPHCInvalidFormat},
		{"excessive time", "$argon2id$v=19$m=65536,t=2000,p=4$salt$hash", ErrPHCInvalidFormat},
		{"invalid salt encoding", "$argon2id$v=19$m=65536,t=3,p=4$!!!invalid!!!$hash", ErrPHCInvalidSalt},
		{"invalid hash encoding", "$argon2id$v=19$m=65536,t=3,p=4$" +
			base64.RawStdEncoding.EncodeToString([]byte("salt12345678")) + "$!!!invalid!!!", ErrPHCInvalidHash},
		{"short salt", "$argon2id$v=19$m=65536,t=3,p=4$" +
			base64.RawStdEncoding.EncodeToString([]byte("short")) + "$" +
			base64.RawStdEncoding.EncodeToString([]byte("hash1234567890123456")), ErrPHCInvalidSalt},
		{"short hash", "$argon2id$v=19$m=65536,t=3,p=4$" +
			base64.RawStdEncoding.EncodeToString([]byte("salt12345678")) + "$" +
			base64.RawStdEncoding.EncodeToString([]byte("short")), ErrPHCInvalidHash},
		{"too few parts", "$argon2id$v=19$m=65536,t=3,p=4", ErrPHCInvalidFormat},
		{"too many parts", "$argon2id$v=19$m=65536,t=3,p=4$salt$hash$extra", ErrPHCInvalidFormat},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePHCHashFormat(tc.hash)
			assert.ErrorIs(t, err, tc.wantErr, "Test case: %s", tc.name)
		})
	}

	// Test that validation doesn't require password
	err = ValidatePHCHashFormat(validHash)
	assert.NoError(t, err, "Should validate format without password")

	// Verify that a validated hash can still be used for verification
	err = ValidatePHCHashFormat(validHash)
	require.NoError(t, err)
	err = VerifyPassword("testPassword123", validHash)
	assert.NoError(t, err, "Validated hash should still work for password verification")
}