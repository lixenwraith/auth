// FILE: auth/scram.go
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// SCRAM-SHA256 implementation

// Credential stores SCRAM authentication data
type Credential struct {
	Username     string
	Salt         []byte
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	StoredKey    []byte // SHA256(ClientKey)
	ServerKey    []byte
}

// Export returns credential as config-friendly map
func (c *Credential) Export() map[string]any {
	return map[string]any{
		"username":      c.Username,
		"salt":          base64.StdEncoding.EncodeToString(c.Salt),
		"argon_time":    c.ArgonTime,
		"argon_memory":  c.ArgonMemory,
		"argon_threads": c.ArgonThreads,
		"stored_key":    base64.StdEncoding.EncodeToString(c.StoredKey),
		"server_key":    base64.StdEncoding.EncodeToString(c.ServerKey),
	}
}

// ImportCredential creates credential from map
func ImportCredential(data map[string]any) (*Credential, error) {
	username, ok := data["username"].(string)
	if !ok {
		return nil, ErrCredMissingUsername
	}

	saltStr, ok := data["salt"].(string)
	if !ok {
		return nil, ErrCredMissingSalt
	}
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, ErrCredInvalidSalt
	}

	// Handle both float64 (from JSON) and int types
	getUint32 := func(key string) (uint32, error) {
		val, ok := data[key]
		if !ok {
			switch key {
			case "argon_time":
				return 0, ErrCredMissingTime
			case "argon_memory":
				return 0, ErrCredMissingMemory
			default:
				return 0, fmt.Errorf("missing %s", key)
			}
		}
		switch v := val.(type) {
		case float64:
			return uint32(v), nil
		case int:
			return uint32(v), nil
		case uint32:
			return v, nil
		default:
			return 0, fmt.Errorf("invalid type for %s", key)
		}
	}

	argonTime, err := getUint32("argon_time")
	if err != nil {
		return nil, err
	}

	argonMemory, err := getUint32("argon_memory")
	if err != nil {
		return nil, err
	}

	threadsVal, ok := data["argon_threads"]
	if !ok {
		return nil, ErrCredMissingThreads
	}
	var argonThreads uint8
	switch v := threadsVal.(type) {
	case float64:
		argonThreads = uint8(v)
	case int:
		argonThreads = uint8(v)
	case uint8:
		argonThreads = v
	default:
		return nil, fmt.Errorf("%w: argon_threads", ErrCredInvalidType)
	}

	storedKeyStr, ok := data["stored_key"].(string)
	if !ok {
		return nil, ErrCredMissingStoredKey
	}
	storedKey, err := base64.StdEncoding.DecodeString(storedKeyStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredInvalidStoredKey, err)
	}

	serverKeyStr, ok := data["server_key"].(string)
	if !ok {
		return nil, ErrCredMissingServerKey
	}
	serverKey, err := base64.StdEncoding.DecodeString(serverKeyStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredInvalidServerKey, err)
	}

	return &Credential{
		Username:     username,
		Salt:         salt,
		ArgonTime:    argonTime,
		ArgonMemory:  argonMemory,
		ArgonThreads: argonThreads,
		StoredKey:    storedKey,
		ServerKey:    serverKey,
	}, nil
}

// DeriveCredential creates SCRAM credential from password
func DeriveCredential(username, password string, salt []byte, time, memory uint32, threads uint8) (*Credential, error) {
	if len(salt) < 16 {
		return nil, ErrSCRAMSaltTooShort
	}

	if time == 0 || memory == 0 || threads == 0 {
		return nil, ErrSCRAMZeroParams
	}

	// Derive salted password using Argon2id
	saltedPassword := argon2.IDKey([]byte(password), salt, time, memory, threads, DefaultArgonKeyLen)

	// Derive keys
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
	}, nil
}

// ScramServer handles server-side SCRAM authentication
type ScramServer struct {
	credentials map[string]*Credential
	handshakes  map[string]*HandshakeState
	mu          sync.RWMutex
}

// HandshakeState tracks ongoing authentication
type HandshakeState struct {
	Username    string
	ClientNonce string
	ServerNonce string
	FullNonce   string
	Credential  *Credential
	CreatedAt   time.Time
	verifying   int32 // Atomic flag to prevent race during verification
}

// NewScramServer creates SCRAM server
func NewScramServer() *ScramServer {
	return &ScramServer{
		credentials: make(map[string]*Credential),
		handshakes:  make(map[string]*HandshakeState),
	}
}

// AddCredential registers user credential
func (s *ScramServer) AddCredential(cred *Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[cred.Username] = cred
}

// ProcessClientFirstMessage processes initial auth request
func (s *ScramServer) ProcessClientFirstMessage(username, clientNonce string) (ServerFirstMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user exists
	cred, exists := s.credentials[username]
	if !exists {
		// Prevent user enumeration - still generate response
		salt := make([]byte, 16)
		rand.Read(salt)
		serverNonce := generateNonce()

		return ServerFirstMessage{
			FullNonce:    clientNonce + serverNonce,
			Salt:         base64.StdEncoding.EncodeToString(salt),
			ArgonTime:    DefaultArgonTime,
			ArgonMemory:  DefaultArgonMemory,
			ArgonThreads: DefaultArgonThreads,
		}, ErrInvalidCredentials
	}

	// Generate server nonce
	serverNonce := generateNonce()
	fullNonce := clientNonce + serverNonce

	// Store handshake state
	state := &HandshakeState{
		Username:    username,
		ClientNonce: clientNonce,
		ServerNonce: serverNonce,
		FullNonce:   fullNonce,
		Credential:  cred,
		CreatedAt:   time.Now(),
		verifying:   0,
	}
	s.handshakes[fullNonce] = state

	// Cleanup old handshakes
	s.cleanupHandshakes()

	return ServerFirstMessage{
		FullNonce:    fullNonce,
		Salt:         base64.StdEncoding.EncodeToString(cred.Salt),
		ArgonTime:    cred.ArgonTime,
		ArgonMemory:  cred.ArgonMemory,
		ArgonThreads: cred.ArgonThreads,
	}, nil
}

// ProcessClientFinalMessage verifies client proof
func (s *ScramServer) ProcessClientFinalMessage(fullNonce, clientProof string) (ServerFinalMessage, error) {
	s.mu.RLock()
	state, exists := s.handshakes[fullNonce]
	s.mu.RUnlock()

	if !exists {
		return ServerFinalMessage{}, ErrSCRAMInvalidNonce
	}

	// Mark as verifying to prevent deletion race
	if !atomic.CompareAndSwapInt32(&state.verifying, 0, 1) {
		return ServerFinalMessage{}, ErrSCRAMVerifyInProgress
	}
	defer func() {
		atomic.StoreInt32(&state.verifying, 0)
		// Safe to delete after verification completes
		s.mu.Lock()
		delete(s.handshakes, fullNonce)
		s.mu.Unlock()
	}()

	// Check timeout
	if time.Since(state.CreatedAt) > 60*time.Second {
		return ServerFinalMessage{}, ErrSCRAMTimeout
	}

	// Decode client proof
	clientProofBytes, err := base64.StdEncoding.DecodeString(clientProof)
	if err != nil {
		return ServerFinalMessage{}, ErrSCRAMInvalidProof
	}

	// Build auth message
	clientFirstBare := fmt.Sprintf("u=%s,n=%s", state.Username, state.ClientNonce)
	serverFirst := ServerFirstMessage{
		FullNonce:    state.FullNonce,
		Salt:         base64.StdEncoding.EncodeToString(state.Credential.Salt),
		ArgonTime:    state.Credential.ArgonTime,
		ArgonMemory:  state.Credential.ArgonMemory,
		ArgonThreads: state.Credential.ArgonThreads,
	}
	clientFinalBare := fmt.Sprintf("r=%s", fullNonce)
	authMessage := clientFirstBare + "," + serverFirst.Marshal() + "," + clientFinalBare

	// Compute client signature
	clientSignature := computeHMAC(state.Credential.StoredKey, []byte(authMessage))

	// XOR to get ClientKey
	if len(clientProofBytes) != len(clientSignature) {
		return ServerFinalMessage{}, ErrSCRAMInvalidProofLen
	}
	clientKey := xorBytes(clientProofBytes, clientSignature)

	// Verify by computing StoredKey
	computedStoredKey := sha256.Sum256(clientKey)
	if subtle.ConstantTimeCompare(computedStoredKey[:], state.Credential.StoredKey) != 1 {
		return ServerFinalMessage{}, ErrInvalidCredentials
	}

	// Generate server signature for mutual auth
	serverSignature := computeHMAC(state.Credential.ServerKey, []byte(authMessage))

	return ServerFinalMessage{
		ServerSignature: base64.StdEncoding.EncodeToString(serverSignature),
		Username:        state.Username,
	}, nil
}

func (s *ScramServer) cleanupHandshakes() {
	cutoff := time.Now().Add(-60 * time.Second)
	for nonce, state := range s.handshakes {
		if state.CreatedAt.Before(cutoff) && atomic.LoadInt32(&state.verifying) == 0 {
			delete(s.handshakes, nonce)
		}
	}
}

// ScramClient handles client-side SCRAM authentication
type ScramClient struct {
	Username    string
	Password    string
	clientNonce string
	serverFirst *ServerFirstMessage
	authMessage string
	serverKey   []byte
	startTime   time.Time // Track handshake start
}

// NewScramClient creates SCRAM client
func NewScramClient(username, password string) *ScramClient {
	return &ScramClient{
		Username: username,
		Password: password,
	}
}

// StartAuthentication generates initial client message
func (c *ScramClient) StartAuthentication() (ClientFirstRequest, error) {
	c.startTime = time.Now()

	// Generate client nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return ClientFirstRequest{}, ErrSCRAMNonceGenFailed
	}
	c.clientNonce = base64.StdEncoding.EncodeToString(nonce)

	return ClientFirstRequest{
		Username:    c.Username,
		ClientNonce: c.clientNonce,
	}, nil
}

// ProcessServerFirstMessage handles server challenge
func (c *ScramClient) ProcessServerFirstMessage(msg ServerFirstMessage) (ClientFinalRequest, error) {
	// Check timeout (30 seconds)
	if !c.startTime.IsZero() && time.Since(c.startTime) > 30*time.Second {
		return ClientFinalRequest{}, ErrSCRAMTimeout
	}

	c.serverFirst = &msg

	// Handle enumeration prevention - server may send fake response
	// We still process it normally and let verification fail later

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(msg.Salt)
	if err != nil {
		return ClientFinalRequest{}, ErrSCRAMInvalidSalt
	}

	// Validate parameters
	if msg.ArgonTime == 0 || msg.ArgonMemory == 0 || msg.ArgonThreads == 0 {
		return ClientFinalRequest{}, ErrSCRAMZeroParams
	}

	// Derive keys using Argon2id
	saltedPassword := argon2.IDKey([]byte(c.Password), salt, msg.ArgonTime, msg.ArgonMemory, msg.ArgonThreads, 32)

	clientKey := computeHMAC(saltedPassword, []byte("Client Key"))
	serverKey := computeHMAC(saltedPassword, []byte("Server Key"))
	storedKey := sha256.Sum256(clientKey)

	// Build auth message
	clientFirstBare := fmt.Sprintf("u=%s,n=%s", c.Username, c.clientNonce)
	clientFinalBare := fmt.Sprintf("r=%s", msg.FullNonce)
	c.authMessage = clientFirstBare + "," + msg.Marshal() + "," + clientFinalBare

	// Compute client proof
	clientSignature := computeHMAC(storedKey[:], []byte(c.authMessage))
	clientProof := xorBytes(clientKey, clientSignature)

	// Store server key for verification
	c.serverKey = serverKey

	return ClientFinalRequest{
		FullNonce:   msg.FullNonce,
		ClientProof: base64.StdEncoding.EncodeToString(clientProof),
	}, nil
}

// VerifyServerFinalMessage validates server signature
func (c *ScramClient) VerifyServerFinalMessage(msg ServerFinalMessage) error {
	// Check timeout
	if !c.startTime.IsZero() && time.Since(c.startTime) > 30*time.Second {
		return ErrSCRAMTimeout
	}

	if c.authMessage == "" || c.serverKey == nil {
		return ErrSCRAMInvalidState
	}

	// Compute expected server signature
	expectedSig := computeHMAC(c.serverKey, []byte(c.authMessage))

	// Decode received signature
	receivedSig, err := base64.StdEncoding.DecodeString(msg.ServerSignature)
	if err != nil {
		return ErrSCRAMServerAuthFailed
	}

	// Constant-time comparison
	if subtle.ConstantTimeCompare(expectedSig, receivedSig) != 1 {
		return ErrSCRAMServerAuthFailed
	}

	return nil
}

// Reset clears client state for retry
func (c *ScramClient) Reset() {
	c.clientNonce = ""
	c.serverFirst = nil
	c.authMessage = ""
	c.serverKey = nil
	c.startTime = time.Time{}
}

// SCRAM message types
type ClientFirstRequest struct {
	Username    string `json:"username"`
	ClientNonce string `json:"client_nonce"`
}

type ServerFirstMessage struct {
	FullNonce    string `json:"full_nonce"`
	Salt         string `json:"salt"`
	ArgonTime    uint32 `json:"argon_time"`
	ArgonMemory  uint32 `json:"argon_memory"`
	ArgonThreads uint8  `json:"argon_threads"`
}

func (s ServerFirstMessage) Marshal() string {
	return fmt.Sprintf("r=%s,s=%s,t=%d,m=%d,p=%d",
		s.FullNonce, s.Salt, s.ArgonTime, s.ArgonMemory, s.ArgonThreads)
}

type ClientFinalRequest struct {
	FullNonce   string `json:"full_nonce"`
	ClientProof string `json:"client_proof"`
}

type ServerFinalMessage struct {
	ServerSignature string `json:"server_signature"`
	Username        string `json:"username,omitempty"`
}

// Helper functions
func computeHMAC(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor length mismatch")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func generateNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}