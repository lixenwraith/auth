// FILE: auth/scram_test.go
package auth

import (
	"testing"

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