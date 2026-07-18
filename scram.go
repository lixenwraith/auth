package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// SCRAM-SHA256 implementation

const (
	// ScramHandshakeTimeout defines maximum time for completing SCRAM handshake
	ScramHandshakeTimeout = 30 * time.Second
	// ScramCleanupInterval defines how often expired handshakes are cleaned
	ScramCleanupInterval = 15 * time.Second
	// ScramMaxHandshakes bounds concurrent in-flight handshakes. Caps memory,
	// not compute: per client-first server cost is one HMAC. Rate limiting
	// upstream remains the control for connection floods.
	ScramMaxHandshakes = 4096
)

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
			// out-of-range float→int conversion is undefined in Go
			if v < 0 || v > math.MaxUint32 || v != math.Trunc(v) {
				return 0, fmt.Errorf("%w: %s", ErrCredInvalidType, key)
			}
			return uint32(v), nil
		case int:
			if v < 0 || int64(v) > math.MaxUint32 {
				return 0, fmt.Errorf("%w: %s", ErrCredInvalidType, key)
			}
			return uint32(v), nil
		case uint32:
			return v, nil
		default:
			return 0, fmt.Errorf("%w: %s", ErrCredInvalidType, key)
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
		if v < 0 || v > math.MaxUint8 || v != math.Trunc(v) {
			return nil, fmt.Errorf("%w: argon_threads", ErrCredInvalidType)
		}
		argonThreads = uint8(v)
	case int:
		if v < 0 || v > math.MaxUint8 {
			return nil, fmt.Errorf("%w: argon_threads", ErrCredInvalidType)
		}
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

	// Post-decode validation
	if argonTime == 0 || argonMemory == 0 || argonThreads == 0 {
		return nil, ErrSCRAMZeroParams
	}
	if err := checkArgonCost(argonMemory, argonTime, argonThreads); err != nil {
		return nil, ErrSCRAMParamsTooLarge
	}
	if len(salt) < 16 {
		return nil, ErrSCRAMSaltTooShort
	}
	if len(storedKey) != sha256.Size {
		return nil, ErrCredInvalidStoredKey
	}
	if len(serverKey) != sha256.Size {
		return nil, ErrCredInvalidServerKey
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

	if len(password) > MaxPasswordLen {
		return nil, ErrPasswordTooLong
	}

	saltedPassword := argon2.IDKey([]byte(password), salt, time, memory, threads, DefaultArgonKeyLen)
	return credentialFromSaltedPassword(username, saltedPassword, salt, time, memory, threads), nil
}

// HandshakeState tracks ongoing authentication
type HandshakeState struct {
	Username    string
	ClientNonce string
	ServerNonce string
	FullNonce   string
	Credential  *Credential
	CreatedAt   time.Time
	verifying   atomic.Int32 // Atomic flag to prevent race during verification
}

// ScramServer handles server-side SCRAM authentication
type ScramServer struct {
	credentials   map[string]*Credential
	handshakes    map[string]*HandshakeState
	decoyKey      []byte     // HMAC key for stable decoy salts
	decoyTemplate Credential // param/salt-length shape mirrored to unknown users
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	cleanupStop   chan struct{}
	stopOnce      sync.Once
}

// NewScramServer creates SCRAM server
func NewScramServer() *ScramServer {
	decoyKey := make([]byte, 32)
	rand.Read(decoyKey)
	s := &ScramServer{
		credentials:   make(map[string]*Credential),
		handshakes:    make(map[string]*HandshakeState),
		decoyKey:      decoyKey,
		cleanupTicker: time.NewTicker(ScramCleanupInterval),
		cleanupStop:   make(chan struct{}),
	}

	go s.cleanupLoop()

	return s
}

// decoySalt generates stable decoy salt; indistinguishable across repeated probes
func (s *ScramServer) decoySalt(username string) []byte {
	n := len(s.decoyTemplate.Salt)
	if n < 16 {
		n = DefaultArgonSaltLen
	}
	out := make([]byte, 0, n)
	for i := 0; len(out) < n; i++ {
		out = append(out, computeHMAC(s.decoyKey, fmt.Appendf(nil, "%s|%d", username, i))...)
	}
	return out[:n]
}

// Stop gracefully shuts down the server and cleanup goroutine
func (s *ScramServer) Stop() {
	s.stopOnce.Do(func() {
		close(s.cleanupStop)
		s.cleanupTicker.Stop()
	})
}

// cleanupLoop runs periodic cleanup of expired handshakes
func (s *ScramServer) cleanupLoop() {
	for {
		select {
		case <-s.cleanupTicker.C:
			s.cleanupExpiredHandshakes()
		case <-s.cleanupStop:
			return
		}
	}
}

// locking split from sweep logic
func (s *ScramServer) cleanupExpiredHandshakes() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
}

// evictExpiredLocked removes timed-out handshakes. Caller holds s.mu.
func (s *ScramServer) evictExpiredLocked() {
	cutoff := time.Now().Add(-ScramHandshakeTimeout)
	for nonce, state := range s.handshakes {
		if state.CreatedAt.Before(cutoff) && state.verifying.Load() == 0 {
			delete(s.handshakes, nonce)
		}
	}
}

// ProcessClientFirstMessage processes initial auth request
//
// An unknown username does NOT produce an error here. The server returns
// a deterministic decoy salt and stores a decoy handshake so that failure
// surfaces only at ProcessClientFinalMessage as ErrInvalidCredentials, matching
// the wrong-password path. Callers must not treat a successful return as
// evidence that the account exists, and must not log it as an auth success.
//
// ErrSCRAMTooManyHandshakes is returned when the in-flight handshake cap is
// reached; the cap is applied before credential lookup so the rejection path is
// identical for known and unknown users.
func (s *ScramServer) ProcessClientFirstMessage(username, clientNonce string) (ServerFirstMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// opportunistic sweep, then hard cap. Applied before the credential
	// lookup so the rejection path is identical for known and unknown users.
	if len(s.handshakes) >= ScramMaxHandshakes {
		s.evictExpiredLocked()
		if len(s.handshakes) >= ScramMaxHandshakes {
			return ServerFirstMessage{}, ErrSCRAMTooManyHandshakes
		}
	}

	// Generate server nonce
	serverNonce := rand.Text()
	fullNonce := clientNonce + serverNonce

	// Check if user exists
	cred, exists := s.credentials[username]
	if !exists {
		t := s.decoyTemplate // mirror real parameter shape
		if t.ArgonTime == 0 {
			t.ArgonTime, t.ArgonMemory, t.ArgonThreads = DefaultArgonTime, DefaultArgonMemory, DefaultArgonThreads
		}
		// Deterministic salt + stored decoy handshake so the final
		// step fails with ErrInvalidCredentials, matching the wrong-password path.
		decoy := &Credential{
			Username:     username,
			Salt:         s.decoySalt(username),
			ArgonTime:    t.ArgonTime,
			ArgonMemory:  t.ArgonMemory,
			ArgonThreads: t.ArgonThreads,
			StoredKey:    make([]byte, sha256.Size), // never matches a real proof
			ServerKey:    make([]byte, sha256.Size),
		}
		s.handshakes[fullNonce] = &HandshakeState{
			Username: username, ClientNonce: clientNonce, ServerNonce: serverNonce,
			FullNonce: fullNonce, Credential: decoy, CreatedAt: time.Now(),
		}
		return ServerFirstMessage{
			FullNonce:    fullNonce,
			Salt:         base64.StdEncoding.EncodeToString(decoy.Salt),
			ArgonTime:    decoy.ArgonTime,
			ArgonMemory:  decoy.ArgonMemory,
			ArgonThreads: decoy.ArgonThreads,
		}, nil // No early error → same control flow as valid user
	}

	s.handshakes[fullNonce] = &HandshakeState{
		Username: username, ClientNonce: clientNonce, ServerNonce: serverNonce,
		FullNonce: fullNonce, Credential: cred, CreatedAt: time.Now(),
	}
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
	// ookup + CAS under one write lock; closes the sweep race
	s.mu.Lock()
	state, exists := s.handshakes[fullNonce]
	if !exists {
		s.mu.Unlock()
		return ServerFinalMessage{}, ErrSCRAMInvalidNonce
	}
	ok := state.verifying.CompareAndSwap(0, 1)
	s.mu.Unlock()
	if !ok {
		return ServerFinalMessage{}, ErrSCRAMVerifyInProgress
	}

	defer func() {
		state.verifying.Store(0)
		// Safe to delete after verification completes
		s.mu.Lock()
		delete(s.handshakes, fullNonce)
		s.mu.Unlock()
	}()

	// Check timeout
	if time.Since(state.CreatedAt) > ScramHandshakeTimeout {
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
	clientKey := make([]byte, len(clientProofBytes))
	subtle.XORBytes(clientKey, clientProofBytes, clientSignature)

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

// AddCredential registers user credential
func (s *ScramServer) AddCredential(cred *Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[cred.Username] = cred
	s.decoyTemplate = Credential{
		Salt:         make([]byte, len(cred.Salt)),
		ArgonTime:    cred.ArgonTime,
		ArgonMemory:  cred.ArgonMemory,
		ArgonThreads: cred.ArgonThreads,
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
	// Reject oversized password before the handshake commits to a KDF pass
	if len(c.Password) > MaxPasswordLen {
		return ClientFirstRequest{}, ErrPasswordTooLong
	}

	c.startTime = time.Now()

	// Generate client nonce
	c.clientNonce = rand.Text()

	return ClientFirstRequest{
		Username:    c.Username,
		ClientNonce: c.clientNonce,
	}, nil
}

// ProcessServerFirstMessage handles server challenge
func (c *ScramClient) ProcessServerFirstMessage(msg ServerFirstMessage) (ClientFinalRequest, error) {
	// Check timeout
	if !c.startTime.IsZero() && time.Since(c.startTime) > ScramHandshakeTimeout {
		return ClientFinalRequest{}, ErrSCRAMTimeout
	}

	c.serverFirst = &msg

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(msg.Salt)
	if err != nil {
		return ClientFinalRequest{}, ErrSCRAMInvalidSalt
	}

	// Validate parameters
	if msg.ArgonTime == 0 || msg.ArgonMemory == 0 || msg.ArgonThreads == 0 {
		return ClientFinalRequest{}, ErrSCRAMZeroParams
	}
	// The peer chooses these values. Unbounded, they are a remote OOM
	// against every client that talks to a hostile or compromised server.
	if err := checkArgonCost(msg.ArgonMemory, msg.ArgonTime, msg.ArgonThreads); err != nil {
		return ClientFinalRequest{}, ErrSCRAMParamsTooLarge
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
	clientProof := make([]byte, len(clientKey))
	subtle.XORBytes(clientProof, clientKey, clientSignature)

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
	if !c.startTime.IsZero() && time.Since(c.startTime) > ScramHandshakeTimeout {
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
