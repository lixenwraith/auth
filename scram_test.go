// FILE: auth/scram_test.go
package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupScramTest is a helper to initialize a server and user credential for testing.
// It performs the full Argon2 -> SCRAM migration workflow.
func setupScramTest(t *testing.T) (server *ScramServer, username, password string, cred *Credential) {
	username = "testuser"
	password = "SecurePassword123"

	// 1. Start with an Argon2 PHC hash, as a real application would.
	phcHash, err := HashPassword(password)
	require.NoError(t, err, "Setup failed: could not hash password")

	// 2. Migrate the PHC hash to a SCRAM credential.
	cred, err = MigrateFromPHC(username, password, phcHash)
	require.NoError(t, err, "Setup failed: could not migrate from PHC hash")

	// 3. Create a server and add the new credential.
	server = NewScramServer()
	server.AddCredential(cred)

	return server, username, password, cred
}

// TestScram_FullRoundtrip_Success simulates a complete, successful authentication handshake.
func TestScram_FullRoundtrip_Success(t *testing.T) {
	server, username, password, _ := setupScramTest(t)
	client := NewScramClient(username, password)

	// --- Step 1: Client sends its first message ---
	clientFirst, err := client.StartAuthentication()
	require.NoError(t, err)

	// --- Step 2: Server receives client's message and responds ---
	serverFirst, err := server.ProcessClientFirstMessage(clientFirst.Username, clientFirst.ClientNonce)
	require.NoError(t, err, "Server failed to process client's first message")

	// --- Step 3: Client receives server's message, computes proof ---
	clientFinal, err := client.ProcessServerFirstMessage(serverFirst)
	require.NoError(t, err, "Client failed to process server's first message")

	// --- Step 4: Server receives client's proof and verifies it ---
	serverFinal, err := server.ProcessClientFinalMessage(clientFinal.FullNonce, clientFinal.ClientProof)
	require.NoError(t, err, "Server failed to verify client's final proof")
	assert.NotEmpty(t, serverFinal.ServerSignature, "Server signature should not be empty")

	// --- Step 5: Client verifies server's signature (mutual authentication) ---
	err = client.VerifyServerFinalMessage(serverFinal)
	assert.NoError(t, err, "Client failed to verify server's final signature")

	t.Log("SCRAM full roundtrip successful")
}

// TestScram_FullRoundtrip_WrongPassword ensures authentication fails with an incorrect password.
func TestScram_FullRoundtrip_WrongPassword(t *testing.T) {
	server, username, _, _ := setupScramTest(t)
	// Create a client with the WRONG password
	client := NewScramClient(username, "WrongPassword!!!")

	// Steps 1-3 will appear to succeed, as the client doesn't know the password is wrong yet.
	clientFirst, err := client.StartAuthentication()
	require.NoError(t, err)

	serverFirst, err := server.ProcessClientFirstMessage(clientFirst.Username, clientFirst.ClientNonce)
	require.NoError(t, err)

	clientFinal, err := client.ProcessServerFirstMessage(serverFirst)
	require.NoError(t, err)

	// --- Step 4: Server verification should fail here ---
	_, err = server.ProcessClientFinalMessage(clientFinal.FullNonce, clientFinal.ClientProof)
	assert.ErrorIs(t, err, ErrInvalidCredentials, "Server should reject proof from wrong password")

	t.Log("SCRAM correctly failed for wrong password")
}

// TestScram_FullRoundtrip_UserNotFound tests for user enumeration protection.
// The server should not reveal whether a user exists or not in its first message.
func TestScram_FullRoundtrip_UserNotFound(t *testing.T) {
	server, _, _, _ := setupScramTest(t)
	client := NewScramClient("unknown_user", "any_password")

	clientFirst, err := client.StartAuthentication()
	require.NoError(t, err)

	// --- Step 2: Server should return an error, but also a FAKE response ---
	// This prevents an attacker from knowing if the user exists based on the response structure.
	serverFirst, err := server.ProcessClientFirstMessage(clientFirst.Username, clientFirst.ClientNonce)
	assert.ErrorIs(t, err, ErrInvalidCredentials, "Server should return an error for an unknown user")
	assert.NotEmpty(t, serverFirst.FullNonce, "Server must still provide a nonce to prevent enumeration")
	assert.NotEmpty(t, serverFirst.Salt, "Server must still provide a salt to prevent enumeration")

	t.Log("SCRAM correctly protected against user enumeration")
}

// TestScram_InvalidNonce simulates a replay attack or message mismatch.
func TestScram_InvalidNonce(t *testing.T) {
	server, username, password, _ := setupScramTest(t)
	client := NewScramClient(username, password)

	// Perform the first part of the handshake
	clientFirst, _ := client.StartAuthentication()
	serverFirst, _ := server.ProcessClientFirstMessage(clientFirst.Username, clientFirst.ClientNonce)
	clientFinal, _ := client.ProcessServerFirstMessage(serverFirst)

	// Attempt to finalize with a completely different nonce
	_, err := server.ProcessClientFinalMessage("this-is-a-bad-nonce", clientFinal.ClientProof)
	assert.ErrorIs(t, err, ErrSCRAMInvalidNonce, "Server should reject a final message with an unknown nonce")
}

// TestScram_CredentialImportExport verifies that credentials can be serialized and deserialized correctly.
func TestScram_CredentialImportExport(t *testing.T) {
	_, _, _, originalCred := setupScramTest(t)

	// Export the credential to a map
	exportedData := originalCred.Export()
	require.NotNil(t, exportedData)

	// Assert that required fields exist and are strings (as they are base64 encoded)
	assert.IsType(t, "", exportedData["salt"])
	assert.IsType(t, "", exportedData["stored_key"])
	assert.IsType(t, "", exportedData["server_key"])

	// Import the credential back from the map
	importedCred, err := ImportCredential(exportedData)
	require.NoError(t, err)
	require.NotNil(t, importedCred)

	// Verify that the imported credential is identical to the original
	assert.Equal(t, originalCred.Username, importedCred.Username)
	assert.Equal(t, originalCred.Salt, importedCred.Salt)
	assert.Equal(t, originalCred.ArgonTime, importedCred.ArgonTime)
	assert.Equal(t, originalCred.ArgonMemory, importedCred.ArgonMemory)
	assert.Equal(t, originalCred.ArgonThreads, importedCred.ArgonThreads)
	assert.Equal(t, originalCred.StoredKey, importedCred.StoredKey)
	assert.Equal(t, originalCred.ServerKey, importedCred.ServerKey)

	t.Log("SCRAM credential import/export successful")
}

// TestScramServerCleanup verifies automatic cleanup of expired handshakes
func TestScramServerCleanup(t *testing.T) {
	// Create server with short cleanup interval for testing
	server := NewScramServer()
	defer server.Stop()

	// Add a test credential
	cred := &Credential{
		Username:     "testuser",
		Salt:         []byte("salt1234567890123456"),
		ArgonTime:    1,
		ArgonMemory:  64,
		ArgonThreads: 1,
		StoredKey:    []byte("stored_key_placeholder"),
		ServerKey:    []byte("server_key_placeholder"),
	}
	server.AddCredential(cred)

	// Start multiple handshakes
	var nonces []string
	for i := 0; i < 5; i++ {
		clientNonce := fmt.Sprintf("client-nonce-%d", i)
		msg, err := server.ProcessClientFirstMessage("testuser", clientNonce)
		require.NoError(t, err)
		nonces = append(nonces, msg.FullNonce)
	}

	// Verify all handshakes exist
	server.mu.RLock()
	assert.Len(t, server.handshakes, 5)
	server.mu.RUnlock()

	// Manually set old timestamp for first 3 handshakes
	server.mu.Lock()
	oldTime := time.Now().Add(-2 * ScramHandshakeTimeout)
	count := 0
	for nonce := range server.handshakes {
		if count < 3 {
			server.handshakes[nonce].CreatedAt = oldTime
			count++
		}
	}
	server.mu.Unlock()

	// Trigger cleanup manually
	server.cleanupExpiredHandshakes()

	// Verify only 2 handshakes remain
	server.mu.RLock()
	assert.Len(t, server.handshakes, 2, "Expired handshakes should be cleaned up")
	server.mu.RUnlock()
}

// TestScramConcurrentSameUser verifies multiple concurrent authentications for same user
func TestScramConcurrentSameUser(t *testing.T) {
	server, username, password, _ := setupScramTest(t)
	defer server.Stop()

	// Number of concurrent authentication attempts
	numAttempts := 10
	results := make(chan error, numAttempts)

	var wg sync.WaitGroup
	for i := 0; i < numAttempts; i++ {
		wg.Add(1)
		go func(attempt int) {
			defer wg.Done()

			// Each goroutine performs full authentication
			client := NewScramClient(username, password)

			// Step 1: Client first
			clientFirst, err := client.StartAuthentication()
			if err != nil {
				results <- err
				return
			}

			// Step 2: Server first
			serverFirst, err := server.ProcessClientFirstMessage(clientFirst.Username, clientFirst.ClientNonce)
			if err != nil {
				results <- err
				return
			}

			// Step 3: Client final
			clientFinal, err := client.ProcessServerFirstMessage(serverFirst)
			if err != nil {
				results <- err
				return
			}

			// Step 4: Server final
			serverFinal, err := server.ProcessClientFinalMessage(clientFinal.FullNonce, clientFinal.ClientProof)
			if err != nil {
				results <- err
				return
			}

			// Step 5: Client verify
			err = client.VerifyServerFinalMessage(serverFinal)
			results <- err
		}(i)
	}

	wg.Wait()
	close(results)

	// Verify all attempts succeeded
	successCount := 0
	for err := range results {
		if err == nil {
			successCount++
		} else {
			t.Logf("Auth attempt failed: %v", err)
		}
	}

	assert.Equal(t, numAttempts, successCount,
		"All concurrent authentication attempts should succeed")

	// Verify no handshakes remain after completion
	server.mu.RLock()
	assert.Empty(t, server.handshakes, "All handshakes should be cleaned up after completion")
	server.mu.RUnlock()
}

// TestScramExplicitTimeout verifies timeout enforcement
func TestScramExplicitTimeout(t *testing.T) {
	// Save original timeout and set shorter one for testing
	originalTimeout := ScramHandshakeTimeout
	// Note: Can't modify const at runtime, so we test with delay instead

	server, username, password, _ := setupScramTest(t)
	defer server.Stop()

	client := NewScramClient(username, password)

	// Start authentication
	clientFirst, err := client.StartAuthentication()
	require.NoError(t, err)

	serverFirst, err := server.ProcessClientFirstMessage(clientFirst.Username, clientFirst.ClientNonce)
	require.NoError(t, err)

	// Manually expire the handshake
	server.mu.Lock()
	for nonce := range server.handshakes {
		server.handshakes[nonce].CreatedAt = time.Now().Add(-2 * ScramHandshakeTimeout)
	}
	server.mu.Unlock()

	// Client processes server message (should work, client tracks own timeout)
	clientFinal, err := client.ProcessServerFirstMessage(serverFirst)
	require.NoError(t, err)

	// Server should reject due to timeout
	_, err = server.ProcessClientFinalMessage(clientFinal.FullNonce, clientFinal.ClientProof)
	assert.ErrorIs(t, err, ErrSCRAMTimeout, "Server should reject expired handshake")

	// Test client-side timeout
	client2 := NewScramClient(username, password)
	client2.startTime = time.Now().Add(-2 * ScramHandshakeTimeout)

	_, err = client2.ProcessServerFirstMessage(serverFirst)
	assert.ErrorIs(t, err, ErrSCRAMTimeout, "Client should reject after timeout")

	_ = originalTimeout // Suppress unused variable warning
}