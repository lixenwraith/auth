// FILE: auth/argon2_test.go
package auth

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordHashing(t *testing.T) {
	auth, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err, "Failed to create authenticator")

	password := "testPassword123"

	// Test hashing
	hash, err := auth.HashPassword(password)
	require.NoError(t, err, "Failed to hash password")

	// Verify PHC format
	assert.True(t, strings.HasPrefix(hash, "$argon2id$"),
		"Hash should have argon2id prefix, got: %s", hash)

	// Test verification with correct password
	err = auth.VerifyPassword(password, hash)
	assert.NoError(t, err, "Failed to verify correct password")

	// Test verification with incorrect password
	err = auth.VerifyPassword("wrongPassword", hash)
	assert.Error(t, err, "Verification should fail for incorrect password")
	assert.Equal(t, ErrInvalidCredentials, err)

	// Test weak password
	_, err = auth.HashPassword("weak")
	assert.Equal(t, ErrWeakPassword, err, "Should reject weak password")

	// Test malformed PHC hash
	err = auth.VerifyPassword(password, "$invalid$format")
	assert.Error(t, err, "Should reject malformed hash")

	// Test corrupted salt
	corruptedHash := strings.Replace(hash, "$argon2id$", "$argon2id$", 1)
	parts := strings.Split(corruptedHash, "$")
	if len(parts) == 6 {
		parts[4] = "invalid!base64"
		corruptedHash = strings.Join(parts, "$")
		err = auth.VerifyPassword(password, corruptedHash)
		assert.Error(t, err, "Should reject corrupted salt")
	}
}

func TestEmptyPasswordAfterValidation(t *testing.T) {
	auth, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err)

	// Empty password should be rejected by length check
	_, err = auth.HashPassword("")
	assert.Equal(t, ErrWeakPassword, err)

	// 8-character password should pass
	hash, err := auth.HashPassword("12345678")
	require.NoError(t, err)

	err = auth.VerifyPassword("12345678", hash)
	assert.NoError(t, err)
}

func TestConcurrentPasswordOperations(t *testing.T) {
	auth, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err)

	password := "testPassword123"
	hash, err := auth.HashPassword(password)
	require.NoError(t, err)

	// Test concurrent verification
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := auth.VerifyPassword(password, hash)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

func TestPHCMigration(t *testing.T) {
	auth, err := NewAuthenticator([]byte("test-secret-key-must-be-32-bytes"))
	require.NoError(t, err)

	password := "testPassword123"
	username := "migrationUser"

	// Generate PHC hash
	phcHash, err := auth.HashPassword(password)
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