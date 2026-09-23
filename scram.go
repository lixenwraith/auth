package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

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
	MaxUsernameLen     = 256
	MaxClientNonceLen  = 256
	MaxFullNonceLen    = 512
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
	salt, err := decodeBase64(saltStr, base64.StdEncoding, MaxArgonSaltLen)
	if err != nil {
		return nil, ErrCredInvalidSalt
	}

	getNumber := func(key string, bits int, missing error) (uint64, error) {
		v, ok := data[key]
		if !ok {
			return 0, missing
		}
		n, err := credentialNumber(v, bits)
		if err != nil {
			return 0, fmt.Errorf("%w: %s", ErrCredInvalidType, key)
		}
		return n, nil
	}
	t, err := getNumber("argon_time", 32, ErrCredMissingTime)
	if err != nil {
		return nil, err
	}
	m, err := getNumber("argon_memory", 32, ErrCredMissingMemory)
	if err != nil {
		return nil, err
	}
	p, err := getNumber("argon_threads", 8, ErrCredMissingThreads)
	if err != nil {
		return nil, err
	}

	storedKeyStr, ok := data["stored_key"].(string)
	if !ok {
		return nil, ErrCredMissingStoredKey
	}
	storedKey, err := decodeBase64(storedKeyStr, base64.StdEncoding, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredInvalidStoredKey, err)
	}

	serverKeyStr, ok := data["server_key"].(string)
	if !ok {
		return nil, ErrCredMissingServerKey
	}
	serverKey, err := decodeBase64(serverKeyStr, base64.StdEncoding, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredInvalidServerKey, err)
	}

	c := &Credential{
		Username: username, Salt: salt,
		ArgonTime: uint32(t), ArgonMemory: uint32(m), ArgonThreads: uint8(p),
		StoredKey: storedKey, ServerKey: serverKey,
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func credentialNumber(value any, bits int) (uint64, error) {
	var n uint64
	switch v := value.(type) {
	case json.Number:
		return strconv.ParseUint(string(v), 10, bits)
	case float64:
		if math.IsNaN(v) || v < 0 || v > math.MaxUint32 || v != math.Trunc(v) {
			return 0, ErrCredInvalidType
		}
		n = uint64(v)
	case int:
		if v < 0 {
			return 0, ErrCredInvalidType
		}
		n = uint64(v)
	case int64:
		if v < 0 {
			return 0, ErrCredInvalidType
		}
		n = uint64(v)
	case uint:
		n = uint64(v)
	case uint64:
		n = v
	case uint32:
		n = uint64(v)
	case uint8:
		n = uint64(v)
	default:
		return 0, ErrCredInvalidType
	}
	if n > (uint64(1)<<bits)-1 {
		return 0, ErrCredInvalidType
	}
	return n, nil
}

// Validate checks a credential before persistence or registration. Credentials
// use one deployment-wide KDF profile to avoid revealing account existence.
func (c *Credential) Validate() error {
	if c == nil {
		return ErrInvalidCredentials
	}
	if err := validateUsername(c.Username); err != nil {
		return err
	}
	if err := validateSalt(c.Salt); err != nil {
		return err
	}
	if err := checkScramCost(c.ArgonMemory, c.ArgonTime, c.ArgonThreads); err != nil {
		return err
	}
	if len(c.StoredKey) != sha256.Size {
		return ErrCredInvalidStoredKey
	}
	if len(c.ServerKey) != sha256.Size {
		return ErrCredInvalidServerKey
	}
	return nil
}

func validateUsername(username string) error {
	if username == "" || len(username) > MaxUsernameLen || !utf8.ValidString(username) {
		return ErrSCRAMInvalidUsername
	}
	for _, r := range username {
		if r == ',' || r == '=' || unicode.IsControl(r) {
			return ErrSCRAMInvalidUsername
		}
	}
	return nil
}

func validNonce(nonce string, maxLen int) bool {
	if len(nonce) == 0 || len(nonce) > maxLen {
		return false
	}
	for i := range nonce {
		if nonce[i] < 0x21 || nonce[i] > 0x7e || nonce[i] == ',' {
			return false
		}
	}
	return true
}

func validateSalt(salt []byte) error {
	if len(salt) < DefaultArgonSaltLen {
		return ErrSCRAMSaltTooShort
	}
	if len(salt) > MaxArgonSaltLen {
		return ErrSCRAMSaltTooLong
	}
	return nil
}

func checkScramCost(memory, time uint32, threads uint8) error {
	if time == 0 || threads == 0 || memory < 8*uint32(threads) {
		return ErrSCRAMZeroParams
	}
	if err := checkArgonCost(memory, time, threads); err != nil {
		return ErrSCRAMParamsTooLarge
	}
	return nil
}

// NewCredential provisions a credential with a fresh random salt and one KDF
// pass. The same options and password policy as HashPassword apply.
func NewCredential(username, password string, opts ...Option) (*Credential, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if len(password) < 8 {
		return nil, ErrWeakPassword
	}
	params := &argonParams{time: DefaultArgonTime, memory: DefaultArgonMemory, threads: DefaultArgonThreads}
	for _, opt := range opts {
		if opt != nil {
			opt(params)
		}
	}
	salt := make([]byte, DefaultArgonSaltLen)
	rand.Read(salt)
	return DeriveCredential(username, password, salt, params.time, params.memory, params.threads)
}

// DeriveCredential creates SCRAM credential from password
func DeriveCredential(username, password string, salt []byte, time, memory uint32, threads uint8) (*Credential, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if err := validateSalt(salt); err != nil {
		return nil, err
	}
	if err := checkScramCost(memory, time, threads); err != nil {
		return nil, err
	}
	if len(password) > MaxPasswordLen {
		return nil, ErrPasswordTooLong
	}

	saltedPassword := argon2.IDKey([]byte(password), salt, time, memory, threads, DefaultArgonKeyLen)
	defer clear(saltedPassword)
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
	stopped       bool
}

// NewScramServer uses a random per-instance decoy key. For restarts or replicas,
// use NewScramServerWithDecoyKey with a stable, shared, secret key.
func NewScramServer() *ScramServer {
	key := make([]byte, 32)
	rand.Read(key)
	s, _ := NewScramServerWithDecoyKey(key)
	clear(key)
	return s
}

// NewScramServerWithDecoyKey keeps unknown-user salts stable across restarts and
// replicas. Persist a cryptographically random key separately from credentials.
func NewScramServerWithDecoyKey(key []byte) (*ScramServer, error) {
	if len(key) < 32 {
		return nil, ErrSCRAMDecoyKey
	}
	s := &ScramServer{
		credentials: make(map[string]*Credential), handshakes: make(map[string]*HandshakeState),
		decoyKey:      append([]byte(nil), key...),
		cleanupTicker: time.NewTicker(ScramCleanupInterval), cleanupStop: make(chan struct{}),
	}
	go s.cleanupLoop()
	return s, nil
}

// decoySalt generates a stable, username-specific decoy salt.
func (s *ScramServer) decoySalt(username string) []byte {
	n := len(s.decoyTemplate.Salt)
	if n < 16 {
		n = DefaultArgonSaltLen
	}
	out := make([]byte, 0, n)
	for i := 0; len(out) < n; i++ {
		out = append(out, computeHMAC(s.decoyKey, fmt.Appendf(nil, "auth/scram/decoy|%s|%d", username, i))...)
	}
	return out[:n]
}

// Stop gracefully shuts down the server and cleanup goroutine
func (s *ScramServer) Stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		clear(s.handshakes)
		clear(s.credentials)
		clear(s.decoyKey)
		s.mu.Unlock()
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
	if err := validateUsername(username); err != nil {
		return ServerFirstMessage{}, err
	}
	if !validNonce(clientNonce, MaxClientNonceLen) {
		return ServerFirstMessage{}, ErrSCRAMInvalidNonce
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return ServerFirstMessage{}, ErrSCRAMStopped
	}

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

	// Do the decoy work for known users as well, reducing first-message timing
	// differences. Uniform response profiles and application rate limits remain
	// necessary; this is not a constant-time network service.
	t := s.decoyTemplate
	if t.ArgonTime == 0 {
		t.ArgonTime, t.ArgonMemory, t.ArgonThreads = DefaultArgonTime, DefaultArgonMemory, DefaultArgonThreads
	}
	cred := &Credential{
		Username: username, Salt: s.decoySalt(username),
		ArgonTime: t.ArgonTime, ArgonMemory: t.ArgonMemory, ArgonThreads: t.ArgonThreads,
		StoredKey: make([]byte, sha256.Size), ServerKey: make([]byte, sha256.Size),
	}
	if registered, exists := s.credentials[username]; exists {
		cred = registered
	}
	s.handshakes[fullNonce] = &HandshakeState{
		Username: username, ClientNonce: clientNonce, ServerNonce: serverNonce,
		FullNonce: fullNonce, Credential: cred, CreatedAt: time.Now(),
	}
	return ServerFirstMessage{
		FullNonce: fullNonce, Salt: base64.StdEncoding.EncodeToString(cred.Salt),
		ArgonTime: cred.ArgonTime, ArgonMemory: cred.ArgonMemory, ArgonThreads: cred.ArgonThreads,
	}, nil
}

// ProcessClientFinalMessage verifies client proof
func (s *ScramServer) ProcessClientFinalMessage(fullNonce, clientProof string) (ServerFinalMessage, error) {
	if !validNonce(fullNonce, MaxFullNonceLen) {
		return ServerFinalMessage{}, ErrSCRAMInvalidNonce
	}
	// Lookup + CAS under one write lock; closes the sweep race
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return ServerFinalMessage{}, ErrSCRAMStopped
	}
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
		// Keep the claim set until deletion: resetting it first permits replay.
		s.mu.Lock()
		delete(s.handshakes, fullNonce)
		s.mu.Unlock()
	}()

	// Check timeout
	if time.Since(state.CreatedAt) > ScramHandshakeTimeout {
		return ServerFinalMessage{}, ErrSCRAMTimeout
	}

	// Decode client proof
	if len(clientProof) > base64.StdEncoding.EncodedLen(sha256.Size) {
		return ServerFinalMessage{}, ErrSCRAMInvalidProofLen
	}
	clientProofBytes, err := decodeBase64(clientProof, base64.StdEncoding, sha256.Size+1)
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
	defer clear(clientKey)
	subtle.XORBytes(clientKey, clientProofBytes, clientSignature)

	// Verify by computing StoredKey
	computedStoredKey := sha256.Sum256(clientKey)
	if subtle.ConstantTimeCompare(computedStoredKey[:], state.Credential.StoredKey) != 1 {
		return ServerFinalMessage{}, ErrInvalidCredentials
	}

	// Linearize successful authentication against credential replacement/removal.
	s.mu.RLock()
	current := s.credentials[state.Username]
	stopped := s.stopped
	s.mu.RUnlock()
	if stopped {
		return ServerFinalMessage{}, ErrSCRAMStopped
	}
	if current != state.Credential {
		return ServerFinalMessage{}, ErrInvalidCredentials
	}

	// Generate server signature for mutual auth
	serverSignature := computeHMAC(state.Credential.ServerKey, []byte(authMessage))

	return ServerFinalMessage{
		ServerSignature: base64.StdEncoding.EncodeToString(serverSignature),
		Username:        state.Username,
	}, nil
}

// AddCredential validates and copies a credential. Replacing one invalidates
// that user's pending handshakes. The caller may reuse its slices after return.
func (s *ScramServer) AddCredential(cred *Credential) error {
	if err := cred.Validate(); err != nil {
		return err
	}
	copy := *cred
	copy.Salt = append([]byte(nil), cred.Salt...)
	copy.StoredKey = append([]byte(nil), cred.StoredKey...)
	copy.ServerKey = append([]byte(nil), cred.ServerKey...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return ErrSCRAMStopped
	}
	t := s.decoyTemplate
	if t.ArgonTime != 0 && (t.ArgonTime != copy.ArgonTime || t.ArgonMemory != copy.ArgonMemory || t.ArgonThreads != copy.ArgonThreads || len(t.Salt) != len(copy.Salt)) {
		return ErrSCRAMCredentialProfile
	}
	s.invalidateHandshakesLocked(copy.Username)
	s.credentials[copy.Username] = &copy
	if t.ArgonTime == 0 {
		s.decoyTemplate = Credential{
			Salt: make([]byte, len(copy.Salt)), ArgonTime: copy.ArgonTime,
			ArgonMemory: copy.ArgonMemory, ArgonThreads: copy.ArgonThreads,
		}
	}
	return nil
}

// RemoveCredential revokes future authentication and all pending handshakes.
// Already issued application sessions/tokens must be revoked by the application.
func (s *ScramServer) RemoveCredential(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.credentials, username)
	s.invalidateHandshakesLocked(username)
}

func (s *ScramServer) invalidateHandshakesLocked(username string) {
	for nonce, state := range s.handshakes {
		if state.Username == username {
			delete(s.handshakes, nonce)
		}
	}
}

type scramClientState uint8

const (
	scramClientIdle scramClientState = iota
	scramClientAwaitChallenge
	scramClientAwaitFinal
)

// ScramClient handles one authentication exchange at a time. It is not safe for
// concurrent use; use a separate client per connection.
type ScramClient struct {
	Username          string
	Password          string
	clientNonce       string
	state             scramClientState
	handshakeUsername string
	authMessage       string
	serverKey         []byte
	startTime         time.Time // Track handshake start
	minArgonTime      uint32
	minArgonMemory    uint32
}

// ScramClientOption configures client policy at construction time.
type ScramClientOption func(*ScramClient)

// WithMinArgonCost sets the minimum accepted iterations and memory (KiB).
// Configure from trusted deployment policy, never from a server challenge.
// The default is DefaultArgonTime and DefaultArgonMemory. StartAuthentication
// rejects invalid configuration; reducing these values weakens password safety.
func WithMinArgonCost(time, memory uint32) ScramClientOption {
	return func(c *ScramClient) {
		c.minArgonTime, c.minArgonMemory = time, memory
	}
}

// NewScramClient creates a client with a minimum KDF cost matching the package's
// production defaults. Override only for a trusted, explicitly chosen profile.
func NewScramClient(username, password string, opts ...ScramClientOption) *ScramClient {
	c := &ScramClient{
		Username:       username,
		Password:       password,
		minArgonTime:   DefaultArgonTime,
		minArgonMemory: DefaultArgonMemory,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// StartAuthentication generates initial client message
func (c *ScramClient) StartAuthentication() (ClientFirstRequest, error) {
	c.Reset()
	if err := checkScramCost(c.minArgonMemory, c.minArgonTime, 1); err != nil {
		return ClientFirstRequest{}, err
	}
	if err := validateUsername(c.Username); err != nil {
		return ClientFirstRequest{}, err
	}
	// Reject oversized password before the handshake commits to a KDF pass
	if len(c.Password) > MaxPasswordLen {
		return ClientFirstRequest{}, ErrPasswordTooLong
	}

	c.startTime = time.Now()
	c.state = scramClientAwaitChallenge
	c.handshakeUsername = c.Username

	// Generate client nonce
	c.clientNonce = rand.Text()

	return ClientFirstRequest{
		Username:    c.Username,
		ClientNonce: c.clientNonce,
	}, nil
}

// ProcessServerFirstMessage handles server challenge
func (c *ScramClient) ProcessServerFirstMessage(msg ServerFirstMessage) (result ClientFinalRequest, err error) {
	defer func() {
		if err != nil {
			c.Reset()
		}
	}()
	if c.state != scramClientAwaitChallenge {
		return ClientFinalRequest{}, ErrSCRAMInvalidState
	}
	if time.Since(c.startTime) > ScramHandshakeTimeout {
		return ClientFinalRequest{}, ErrSCRAMTimeout
	}
	if !validNonce(msg.FullNonce, MaxFullNonceLen) || !strings.HasPrefix(msg.FullNonce, c.clientNonce) || len(msg.FullNonce) <= len(c.clientNonce) {
		return ClientFinalRequest{}, ErrSCRAMInvalidNonce
	}
	// Password is exported for compatibility; check it again immediately before KDF.
	if len(c.Password) > MaxPasswordLen {
		return ClientFinalRequest{}, ErrPasswordTooLong
	}
	salt, err := decodeBase64(msg.Salt, base64.StdEncoding, MaxArgonSaltLen)
	if err != nil {
		return ClientFinalRequest{}, ErrSCRAMInvalidSalt
	}
	if err := validateSalt(salt); err != nil {
		return ClientFinalRequest{}, err
	}
	if err := checkScramCost(msg.ArgonMemory, msg.ArgonTime, msg.ArgonThreads); err != nil {
		return ClientFinalRequest{}, err
	}
	if msg.ArgonTime < c.minArgonTime || msg.ArgonMemory < c.minArgonMemory {
		return ClientFinalRequest{}, ErrSCRAMParamsTooSmall
	}

	// Derive keys using Argon2id
	saltedPassword := argon2.IDKey([]byte(c.Password), salt, msg.ArgonTime, msg.ArgonMemory, msg.ArgonThreads, 32)
	defer clear(saltedPassword)

	clientKey := computeHMAC(saltedPassword, []byte("Client Key"))
	defer clear(clientKey)
	serverKey := computeHMAC(saltedPassword, []byte("Server Key"))
	storedKey := sha256.Sum256(clientKey)

	// Build auth message
	clientFirstBare := fmt.Sprintf("u=%s,n=%s", c.handshakeUsername, c.clientNonce)
	clientFinalBare := fmt.Sprintf("r=%s", msg.FullNonce)
	c.authMessage = clientFirstBare + "," + msg.Marshal() + "," + clientFinalBare

	// Compute client proof
	clientSignature := computeHMAC(storedKey[:], []byte(c.authMessage))
	clientProof := make([]byte, len(clientKey))
	subtle.XORBytes(clientProof, clientKey, clientSignature)

	// Store server key for verification
	c.serverKey = serverKey
	if time.Since(c.startTime) > ScramHandshakeTimeout {
		return ClientFinalRequest{}, ErrSCRAMTimeout
	}
	c.state = scramClientAwaitFinal

	return ClientFinalRequest{
		FullNonce:   msg.FullNonce,
		ClientProof: base64.StdEncoding.EncodeToString(clientProof),
	}, nil
}

// VerifyServerFinalMessage validates server signature
func (c *ScramClient) VerifyServerFinalMessage(msg ServerFinalMessage) error {
	defer c.Reset() // consume state on success AND failure
	if c.state != scramClientAwaitFinal {
		return ErrSCRAMInvalidState
	}
	if time.Since(c.startTime) > ScramHandshakeTimeout {
		return ErrSCRAMTimeout
	}
	if msg.Username != "" && msg.Username != c.handshakeUsername {
		return ErrSCRAMServerAuthFailed
	}

	// Compute expected server signature
	expectedSig := computeHMAC(c.serverKey, []byte(c.authMessage))

	// Decode received signature
	receivedSig, err := decodeBase64(msg.ServerSignature, base64.StdEncoding, sha256.Size)
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
	c.state = scramClientIdle
	c.handshakeUsername = ""
	c.authMessage = ""
	clear(c.serverKey)
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
