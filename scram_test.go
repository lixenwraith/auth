package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func newTestServer(t *testing.T) *ScramServer {
	t.Helper()
	s := NewScramServer()
	t.Cleanup(s.Stop)
	return s
}

func testCredential(t *testing.T, username, password string) *Credential {
	t.Helper()
	phcHash, err := HashPassword(password, cheapArgon...)
	noErr(t, err, "HashPassword")
	cred, err := MigrateFromPHC(username, password, phcHash)
	noErr(t, err, "MigrateFromPHC")
	return cred
}

func setupScram(t *testing.T) (*ScramServer, string, string, *Credential) {
	t.Helper()
	const username, password = "testuser", "SecurePassword123"
	cred := testCredential(t, username, password)
	s := newTestServer(t)
	s.AddCredential(cred)
	return s, username, password, cred
}

func handshakeCount(s *ScramServer) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.handshakes)
}

// startHandshake drives a fresh client to the point where a proof is pending.
func startHandshake(t *testing.T, s *ScramServer, username, password string) ClientFinalRequest {
	t.Helper()
	c := NewScramClient(username, password)
	first, err := c.StartAuthentication()
	noErr(t, err, "StartAuthentication")
	serverFirst, err := s.ProcessClientFirstMessage(first.Username, first.ClientNonce)
	noErr(t, err, "ProcessClientFirstMessage")
	final, err := c.ProcessServerFirstMessage(serverFirst)
	noErr(t, err, "ProcessServerFirstMessage")
	return final
}

func runHandshake(s *ScramServer, c *ScramClient) error {
	first, err := c.StartAuthentication()
	if err != nil {
		return err
	}
	serverFirst, err := s.ProcessClientFirstMessage(first.Username, first.ClientNonce)
	if err != nil {
		return err
	}
	final, err := c.ProcessServerFirstMessage(serverFirst)
	if err != nil {
		return err
	}
	serverFinal, err := s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	if err != nil {
		return err
	}
	return c.VerifyServerFinalMessage(serverFinal)
}

func TestScramRoundtrip(t *testing.T) {
	s, user, pw, _ := setupScram(t)
	noErr(t, runHandshake(s, NewScramClient(user, pw)), "handshake")
	eq(t, handshakeCount(s), 0, "handshake retained after success")
}

func TestScramWrongPassword(t *testing.T) {
	s, user, _, _ := setupScram(t)
	errIs(t, runHandshake(s, NewScramClient(user, "WrongPassword!!!")), ErrInvalidCredentials, "wrong password")
	eq(t, handshakeCount(s), 0, "handshake retained after failure")
}

func TestScramUnknownUser(t *testing.T) {
	s, _, _, cred := setupScram(t)
	c := NewScramClient("unknown_user", "any_password")

	first, err := c.StartAuthentication()
	noErr(t, err, "StartAuthentication")

	serverFirst, err := s.ProcessClientFirstMessage(first.Username, first.ClientNonce)
	noErr(t, err, "unknown user must not be signalled at the first message")

	// the decoy must mirror the registered parameter shape
	eq(t, serverFirst.ArgonTime, cred.ArgonTime, "decoy time")
	eq(t, serverFirst.ArgonMemory, cred.ArgonMemory, "decoy memory")
	eq(t, serverFirst.ArgonThreads, cred.ArgonThreads, "decoy threads")
	decoySalt, err := base64.StdEncoding.DecodeString(serverFirst.Salt)
	noErr(t, err, "decoy salt decode")
	eq(t, len(decoySalt), len(cred.Salt), "decoy salt length")

	// stable across probes, distinct per username
	second, err := s.ProcessClientFirstMessage("unknown_user", "probe-2")
	noErr(t, err, "second probe")
	eq(t, second.Salt, serverFirst.Salt, "decoy salt must be deterministic")
	third, err := s.ProcessClientFirstMessage("other_unknown", "probe-3")
	noErr(t, err, "third probe")
	if third.Salt == serverFirst.Salt {
		t.Fatal("decoy salt is not username-bound")
	}

	// failure surfaces only at the proof step, as for a wrong password
	final, err := c.ProcessServerFirstMessage(serverFirst)
	noErr(t, err, "ProcessServerFirstMessage")
	_, err = s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	errIs(t, err, ErrInvalidCredentials, "unknown user")
}

func TestScramDecoySaltIsolation(t *testing.T) {
	// decoyKey is per-instance: a shared decoy salt would be a global oracle
	// for account existence across a cluster.
	a, b := newTestServer(t), newTestServer(t)
	first, err := a.ProcessClientFirstMessage("ghost", "n1")
	noErr(t, err, "server a")
	second, err := b.ProcessClientFirstMessage("ghost", "n2")
	noErr(t, err, "server b")
	if first.Salt == second.Salt {
		t.Fatal("decoy salt is identical across server instances")
	}

	// with no credential registered the template is empty and defaults apply
	raw, err := base64.StdEncoding.DecodeString(first.Salt)
	noErr(t, err, "decode")
	eq(t, len(raw), DefaultArgonSaltLen, "fallback salt length")
	eq(t, first.ArgonTime, uint32(DefaultArgonTime), "fallback time")
	eq(t, first.ArgonMemory, uint32(DefaultArgonMemory), "fallback memory")
	eq(t, first.ArgonThreads, uint8(DefaultArgonThreads), "fallback threads")
}

func TestScramDecoySaltMultiBlock(t *testing.T) {
	s := newTestServer(t)
	cred := testCredential(t, "u", "SecurePassword123")
	cred.Salt = make([]byte, 48) // exceeds one HMAC-SHA256 block
	s.AddCredential(cred)

	msg, err := s.ProcessClientFirstMessage("ghost", "n")
	noErr(t, err, "first message")
	raw, err := base64.StdEncoding.DecodeString(msg.Salt)
	noErr(t, err, "decode")
	eq(t, len(raw), 48, "decoy salt length")
}

func TestScramReplayAndUnknownNonce(t *testing.T) {
	s, user, pw, _ := setupScram(t)
	final := startHandshake(t, s, user, pw)

	_, err := s.ProcessClientFinalMessage("this-is-a-bad-nonce", final.ClientProof)
	errIs(t, err, ErrSCRAMInvalidNonce, "unknown nonce")

	_, err = s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	noErr(t, err, "first proof")

	_, err = s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	errIs(t, err, ErrSCRAMInvalidNonce, "replayed proof")
}

func TestScramProofBinding(t *testing.T) {
	// A proof commits to its own auth message; moving it to another live
	// handshake for the same user must fail.
	s, user, pw, _ := setupScram(t)
	a := startHandshake(t, s, user, pw)
	b := startHandshake(t, s, user, pw)

	_, err := s.ProcessClientFinalMessage(a.FullNonce, b.ClientProof)
	errIs(t, err, ErrInvalidCredentials, "cross-handshake proof")

	// the rejected attempt consumed handshake a but left b intact
	_, err = s.ProcessClientFinalMessage(a.FullNonce, a.ClientProof)
	errIs(t, err, ErrSCRAMInvalidNonce, "handshake a consumed")
	_, err = s.ProcessClientFinalMessage(b.FullNonce, b.ClientProof)
	noErr(t, err, "handshake b unaffected")
}

func TestScramProofEncoding(t *testing.T) {
	s, user, pw, _ := setupScram(t)

	cases := []struct {
		name  string
		proof string
		want  error
	}{
		{"not base64", "!!!not base64!!!", ErrSCRAMInvalidProof},
		{"empty", "", ErrSCRAMInvalidProofLen},
		{"short", base64.StdEncoding.EncodeToString(make([]byte, 16)), ErrSCRAMInvalidProofLen},
		{"long", base64.StdEncoding.EncodeToString(make([]byte, sha256.Size+1)), ErrSCRAMInvalidProofLen},
		{"zeroed", base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)), ErrInvalidCredentials},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			final := startHandshake(t, s, user, pw)
			_, err := s.ProcessClientFinalMessage(final.FullNonce, tc.proof)
			errIs(t, err, tc.want, tc.name)
		})
	}
}

func TestScramVerifyInProgress(t *testing.T) {
	s, user, pw, _ := setupScram(t)
	final := startHandshake(t, s, user, pw)

	s.mu.RLock()
	state := s.handshakes[final.FullNonce]
	s.mu.RUnlock()
	if state == nil {
		t.Fatal("handshake not registered")
	}

	state.verifying.Store(1)
	_, err := s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	errIs(t, err, ErrSCRAMVerifyInProgress, "concurrent verification")

	// the rejected attempt must not consume the handshake
	state.verifying.Store(0)
	_, err = s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	noErr(t, err, "retry after release")
}

func TestScramTimeouts(t *testing.T) {
	s, user, pw, _ := setupScram(t)
	final := startHandshake(t, s, user, pw)

	s.mu.Lock()
	s.handshakes[final.FullNonce].CreatedAt = time.Now().Add(-2 * ScramHandshakeTimeout)
	s.mu.Unlock()

	_, err := s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	errIs(t, err, ErrSCRAMTimeout, "server-side timeout")
	_, err = s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	errIs(t, err, ErrSCRAMInvalidNonce, "expired handshake consumed")

	// client-side clock
	c := NewScramClient(user, pw)
	_, err = c.StartAuthentication()
	noErr(t, err, "StartAuthentication")
	c.startTime = time.Now().Add(-2 * ScramHandshakeTimeout)

	_, err = c.ProcessServerFirstMessage(ServerFirstMessage{
		FullNonce:   "n",
		Salt:        base64.StdEncoding.EncodeToString(make([]byte, 16)),
		ArgonTime:   testArgonTime,
		ArgonMemory: testArgonMemory, ArgonThreads: testArgonThreads,
	})
	errIs(t, err, ErrSCRAMTimeout, "client timeout on server-first")

	c.authMessage = "seeded"
	c.serverKey = make([]byte, sha256.Size)
	errIs(t, c.VerifyServerFinalMessage(ServerFinalMessage{}), ErrSCRAMTimeout, "client timeout on server-final")
}

func TestScramCleanup(t *testing.T) {
	s, user, _, _ := setupScram(t)
	for i := range 5 {
		_, err := s.ProcessClientFirstMessage(user, fmt.Sprintf("client-nonce-%d", i))
		noErr(t, err, "first message")
	}
	eq(t, handshakeCount(s), 5, "registered handshakes")

	s.mu.Lock()
	aged := 0
	for _, state := range s.handshakes {
		if aged == 3 {
			break
		}
		state.CreatedAt = time.Now().Add(-2 * ScramHandshakeTimeout)
		aged++
	}
	s.mu.Unlock()

	s.cleanupExpiredHandshakes()
	eq(t, handshakeCount(s), 2, "after sweep")

	// a handshake under verification survives the sweep regardless of age
	s.mu.Lock()
	for _, state := range s.handshakes {
		state.CreatedAt = time.Now().Add(-2 * ScramHandshakeTimeout)
		state.verifying.Store(1)
	}
	s.mu.Unlock()

	s.cleanupExpiredHandshakes()
	eq(t, handshakeCount(s), 2, "verifying handshakes must not be evicted")
}

func TestScramHandshakeCap(t *testing.T) {
	s, user, _, _ := setupScram(t)
	for i := range ScramMaxHandshakes {
		_, err := s.ProcessClientFirstMessage(user, fmt.Sprintf("n-%d", i))
		noErr(t, err, "first message")
	}
	eq(t, handshakeCount(s), ScramMaxHandshakes, "at capacity")

	_, err := s.ProcessClientFirstMessage(user, "overflow")
	errIs(t, err, ErrSCRAMTooManyHandshakes, "known user at capacity")

	// the cap precedes credential lookup, so it is not an enumeration oracle
	_, err = s.ProcessClientFirstMessage("ghost", "overflow")
	errIs(t, err, ErrSCRAMTooManyHandshakes, "unknown user at capacity")

	s.mu.Lock()
	for _, state := range s.handshakes {
		state.CreatedAt = time.Now().Add(-2 * ScramHandshakeTimeout)
	}
	s.mu.Unlock()

	_, err = s.ProcessClientFirstMessage(user, "after-sweep")
	noErr(t, err, "capacity reclaimed by the opportunistic sweep")
	eq(t, handshakeCount(s), 1, "all expired slots reclaimed")
}

func TestScramNonceUniqueness(t *testing.T) {
	s, user, _, _ := setupScram(t)
	seen := make(map[string]struct{}, 256)
	for range 256 {
		// a fixed client nonce must not produce a fixed full nonce
		msg, err := s.ProcessClientFirstMessage(user, "fixed-client-nonce")
		noErr(t, err, "first message")
		if _, dup := seen[msg.FullNonce]; dup {
			t.Fatalf("duplicate full nonce: %s", msg.FullNonce)
		}
		seen[msg.FullNonce] = struct{}{}
	}
}

func TestScramStopIdempotent(t *testing.T) {
	s := NewScramServer()
	s.Stop()
	s.Stop() // stopOnce must absorb the second close
}

func TestScramClientState(t *testing.T) {
	s, user, pw, _ := setupScram(t)
	c := NewScramClient(user, pw)

	errIs(t, c.VerifyServerFinalMessage(ServerFinalMessage{}), ErrSCRAMInvalidState, "unstarted client")

	first, err := c.StartAuthentication()
	noErr(t, err, "StartAuthentication")
	serverFirst, err := s.ProcessClientFirstMessage(first.Username, first.ClientNonce)
	noErr(t, err, "ProcessClientFirstMessage")
	final, err := c.ProcessServerFirstMessage(serverFirst)
	noErr(t, err, "ProcessServerFirstMessage")
	serverFinal, err := s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	noErr(t, err, "ProcessClientFinalMessage")

	tampered := serverFinal
	tampered.ServerSignature = base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	errIs(t, c.VerifyServerFinalMessage(tampered), ErrSCRAMServerAuthFailed, "forged signature")
	tampered.ServerSignature = "!!!"
	errIs(t, c.VerifyServerFinalMessage(tampered), ErrSCRAMServerAuthFailed, "malformed signature")
	noErr(t, c.VerifyServerFinalMessage(serverFinal), "valid signature")

	c.Reset()
	errIs(t, c.VerifyServerFinalMessage(serverFinal), ErrSCRAMInvalidState, "after reset")
	next, err := c.StartAuthentication()
	noErr(t, err, "restart")
	if next.ClientNonce == first.ClientNonce {
		t.Fatal("client nonce reused after Reset")
	}
}

func TestScramClientRejectsBadServerFirst(t *testing.T) {
	c := NewScramClient("u", "SecurePassword123")
	_, err := c.StartAuthentication()
	noErr(t, err, "StartAuthentication")

	_, err = c.ProcessServerFirstMessage(ServerFirstMessage{
		FullNonce: "n", Salt: "!!!",
		ArgonTime: testArgonTime, ArgonMemory: testArgonMemory, ArgonThreads: testArgonThreads,
	})
	errIs(t, err, ErrSCRAMInvalidSalt, "salt encoding")

	// ☢ no upper bound is applied to server-supplied cost parameters
	good := base64.StdEncoding.EncodeToString(make([]byte, 16))
	for _, msg := range []ServerFirstMessage{
		{FullNonce: "n", Salt: good, ArgonTime: 0, ArgonMemory: testArgonMemory, ArgonThreads: 1},
		{FullNonce: "n", Salt: good, ArgonTime: 1, ArgonMemory: 0, ArgonThreads: 1},
		{FullNonce: "n", Salt: good, ArgonTime: 1, ArgonMemory: testArgonMemory, ArgonThreads: 0},
	} {
		_, err = c.ProcessServerFirstMessage(msg)
		errIs(t, err, ErrSCRAMZeroParams, "zero parameter")
	}

	// A hostile server cannot dictate an unbounded KDF
	_, err = c.ProcessServerFirstMessage(ServerFirstMessage{
		FullNonce: "n", Salt: good,
		ArgonTime: 1, ArgonMemory: MaxVerifyArgonMemory + 1, ArgonThreads: 1,
	})
	errIs(t, err, ErrSCRAMParamsTooLarge, "memory over ceiling")
}

func TestScramClientOversizedPassword(t *testing.T) {
	c := NewScramClient("u", strings.Repeat("a", MaxPasswordLen+1))
	_, err := c.StartAuthentication()
	errIs(t, err, ErrPasswordTooLong, "oversized password rejected before the KDF")
}

func TestServerFirstMessageMarshal(t *testing.T) {
	// the auth message binds this exact encoding; changes break every client
	msg := ServerFirstMessage{
		FullNonce: "abc", Salt: "c2FsdA==",
		ArgonTime: 3, ArgonMemory: 65536, ArgonThreads: 4,
	}
	eq(t, msg.Marshal(), "r=abc,s=c2FsdA==,t=3,m=65536,p=4", "marshal")
}

func TestScramMigratedNonStandardDigest(t *testing.T) {
	// MigrateFromPHC falls back to DeriveCredential for digests other than 32
	// bytes; the resulting credential must still complete a handshake.
	const user, pw = "legacy", "SecurePassword123"
	cred, err := MigrateFromPHC(user, pw, phcFor(pw, []byte("0123456789abcdef"), 20))
	noErr(t, err, "MigrateFromPHC")
	eq(t, len(cred.StoredKey), sha256.Size, "stored key length")

	s := newTestServer(t)
	s.AddCredential(cred)
	noErr(t, runHandshake(s, NewScramClient(user, pw)), "handshake with migrated credential")
}

func TestDeriveCredential(t *testing.T) {
	const pw = "SecurePassword123"
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	first, err := DeriveCredential("u", pw, salt, testArgonTime, testArgonMemory, testArgonThreads)
	noErr(t, err, "DeriveCredential")
	second, err := DeriveCredential("u", pw, salt, testArgonTime, testArgonMemory, testArgonThreads)
	noErr(t, err, "DeriveCredential repeat")
	eqBytes(t, first.StoredKey, second.StoredKey, "deterministic stored key")
	eqBytes(t, first.ServerKey, second.ServerKey, "deterministic server key")

	salted := argon2.IDKey([]byte(pw), salt, testArgonTime, testArgonMemory, testArgonThreads, DefaultArgonKeyLen)
	want := sha256.Sum256(computeHMAC(salted, []byte("Client Key")))
	eqBytes(t, first.StoredKey, want[:], "stored key derivation")
	eqBytes(t, first.ServerKey, computeHMAC(salted, []byte("Server Key")), "server key derivation")
	if bytes.Equal(first.StoredKey, salted) || bytes.Equal(first.ServerKey, salted) {
		t.Fatal("credential exposes the salted password")
	}

	// a different password must not collide
	other, err := DeriveCredential("u", pw+"x", salt, testArgonTime, testArgonMemory, testArgonThreads)
	noErr(t, err, "DeriveCredential other password")
	if bytes.Equal(first.StoredKey, other.StoredKey) {
		t.Fatal("stored key is independent of the password")
	}

	_, err = DeriveCredential("u", pw, make([]byte, 15), testArgonTime, testArgonMemory, testArgonThreads)
	errIs(t, err, ErrSCRAMSaltTooShort, "short salt")

	for _, p := range []struct {
		time, memory uint32
		threads      uint8
	}{{0, testArgonMemory, 1}, {1, 0, 1}, {1, testArgonMemory, 0}} {
		_, err = DeriveCredential("u", pw, salt, p.time, p.memory, p.threads)
		errIs(t, err, ErrSCRAMZeroParams, "zero parameter")
	}

	_, err = DeriveCredential("u", strings.Repeat("a", MaxPasswordLen+1), salt,
		testArgonTime, testArgonMemory, testArgonThreads)
	errIs(t, err, ErrPasswordTooLong, "oversized password")
}

func TestCredentialExportImportRoundTrip(t *testing.T) {
	cred := testCredential(t, "roundtrip", "SecurePassword123")

	imported, err := ImportCredential(cred.Export())
	noErr(t, err, "ImportCredential")
	eq(t, imported.Username, cred.Username, "username")
	eqBytes(t, imported.Salt, cred.Salt, "salt")
	eq(t, imported.ArgonTime, cred.ArgonTime, "time")
	eq(t, imported.ArgonMemory, cred.ArgonMemory, "memory")
	eq(t, imported.ArgonThreads, cred.ArgonThreads, "threads")
	eqBytes(t, imported.StoredKey, cred.StoredKey, "stored key")
	eqBytes(t, imported.ServerKey, cred.ServerKey, "server key")

	// JSON transport converts every number to float64
	raw, err := json.Marshal(cred.Export())
	noErr(t, err, "marshal")
	var decoded map[string]any
	noErr(t, json.Unmarshal(raw, &decoded), "unmarshal")
	viaJSON, err := ImportCredential(decoded)
	noErr(t, err, "import via JSON")
	eq(t, viaJSON.ArgonMemory, cred.ArgonMemory, "memory via JSON")
	eqBytes(t, viaJSON.StoredKey, cred.StoredKey, "stored key via JSON")

	// int-typed input, as produced by YAML and TOML decoders
	m := cred.Export()
	m["argon_time"] = int(cred.ArgonTime)
	m["argon_memory"] = int(cred.ArgonMemory)
	m["argon_threads"] = int(cred.ArgonThreads)
	viaInt, err := ImportCredential(m)
	noErr(t, err, "import from int-typed map")
	eq(t, viaInt.ArgonThreads, cred.ArgonThreads, "threads via int")

	// an imported credential must still authenticate
	s := newTestServer(t)
	s.AddCredential(imported)
	noErr(t, runHandshake(s, NewScramClient("roundtrip", "SecurePassword123")), "handshake after import")
}

func TestImportCredentialErrors(t *testing.T) {
	cred := testCredential(t, "u", "SecurePassword123")
	with := func(mutate func(map[string]any)) map[string]any {
		m := cred.Export()
		mutate(m)
		return m
	}
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

	cases := []struct {
		name string
		data map[string]any
		want error
	}{
		{"empty map", map[string]any{}, ErrCredMissingUsername},
		{"username wrong type", with(func(m map[string]any) { m["username"] = 42 }), ErrCredMissingUsername},

		{"salt missing", with(func(m map[string]any) { delete(m, "salt") }), ErrCredMissingSalt},
		{"salt not base64", with(func(m map[string]any) { m["salt"] = "!!!" }), ErrCredInvalidSalt},
		{"salt too short", with(func(m map[string]any) { m["salt"] = b64(15) }), ErrSCRAMSaltTooShort},

		{"time missing", with(func(m map[string]any) { delete(m, "argon_time") }), ErrCredMissingTime},
		{"time wrong type", with(func(m map[string]any) { m["argon_time"] = "3" }), ErrCredInvalidType},
		{"time fractional", with(func(m map[string]any) { m["argon_time"] = 3.5 }), ErrCredInvalidType},
		{"time negative float", with(func(m map[string]any) { m["argon_time"] = float64(-1) }), ErrCredInvalidType},
		{"time float overflow", with(func(m map[string]any) { m["argon_time"] = float64(math.MaxUint32 + 1) }), ErrCredInvalidType},
		{"time negative int", with(func(m map[string]any) { m["argon_time"] = -1 }), ErrCredInvalidType},
		{"time zero", with(func(m map[string]any) { m["argon_time"] = uint32(0) }), ErrSCRAMZeroParams},

		{"memory missing", with(func(m map[string]any) { delete(m, "argon_memory") }), ErrCredMissingMemory},
		{"memory zero", with(func(m map[string]any) { m["argon_memory"] = uint32(0) }), ErrSCRAMZeroParams},

		{"threads missing", with(func(m map[string]any) { delete(m, "argon_threads") }), ErrCredMissingThreads},
		{"threads wrong type", with(func(m map[string]any) { m["argon_threads"] = "4" }), ErrCredInvalidType},
		{"threads overflow", with(func(m map[string]any) { m["argon_threads"] = float64(256) }), ErrCredInvalidType},
		{"threads negative", with(func(m map[string]any) { m["argon_threads"] = -1 }), ErrCredInvalidType},
		{"threads zero", with(func(m map[string]any) { m["argon_threads"] = uint8(0) }), ErrSCRAMZeroParams},

		{"stored key missing", with(func(m map[string]any) { delete(m, "stored_key") }), ErrCredMissingStoredKey},
		{"stored key not base64", with(func(m map[string]any) { m["stored_key"] = "!!!" }), ErrCredInvalidStoredKey},
		{"stored key short", with(func(m map[string]any) { m["stored_key"] = b64(sha256.Size - 1) }), ErrCredInvalidStoredKey},

		{"server key missing", with(func(m map[string]any) { delete(m, "server_key") }), ErrCredMissingServerKey},
		{"server key not base64", with(func(m map[string]any) { m["server_key"] = "!!!" }), ErrCredInvalidServerKey},
		{"server key short", with(func(m map[string]any) { m["server_key"] = b64(sha256.Size - 1) }), ErrCredInvalidServerKey},

		{"stored key long", with(func(m map[string]any) { m["stored_key"] = b64(sha256.Size + 1) }), ErrCredInvalidStoredKey},
		{"server key long", with(func(m map[string]any) { m["server_key"] = b64(sha256.Size + 1) }), ErrCredInvalidServerKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ImportCredential(tc.data)
			errIs(t, err, tc.want, tc.name)
			if got != nil {
				t.Fatalf("%s: credential returned alongside error", tc.name)
			}
		})
	}
}

func TestScramConcurrentSameUser(t *testing.T) {
	s, user, pw, _ := setupScram(t)

	const n = 12
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- runHandshake(s, NewScramClient(user, pw))
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent handshake: %v", err)
		}
	}
	eq(t, handshakeCount(s), 0, "handshakes leaked")
}

func TestScramConcurrentMixedTraffic(t *testing.T) {
	s := newTestServer(t)
	creds := make([]*Credential, 4)
	for i := range creds {
		creds[i] = testCredential(t, fmt.Sprintf("user-%d", i), "SecurePassword123")
	}

	var wg sync.WaitGroup
	for _, cred := range creds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.AddCredential(cred)
		}()
	}
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// registration races against lookup; both paths take s.mu
			_, _ = s.ProcessClientFirstMessage(fmt.Sprintf("user-%d", i%4), fmt.Sprintf("n-%d", i))
			_, _ = s.ProcessClientFirstMessage(fmt.Sprintf("ghost-%d", i), fmt.Sprintf("g-%d", i))
		}()
	}
	wg.Wait()
}

func FuzzImportCredential(f *testing.F) {
	cred, err := DeriveCredential("u", "SecurePassword123", make([]byte, 16),
		testArgonTime, testArgonMemory, testArgonThreads)
	if err != nil {
		f.Fatal(err)
	}
	seed, err := json.Marshal(cred.Export())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"username":"u","salt":"","argon_time":1e309}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil || m == nil {
			return
		}
		got, err := ImportCredential(m)
		if err != nil {
			if got != nil {
				t.Fatal("credential returned alongside error")
			}
			return
		}
		if len(got.Salt) < 16 {
			t.Fatalf("accepted salt of %d bytes", len(got.Salt))
		}
		if len(got.StoredKey) != sha256.Size || len(got.ServerKey) != sha256.Size {
			t.Fatalf("accepted keys of %d/%d bytes", len(got.StoredKey), len(got.ServerKey))
		}
		if got.ArgonTime == 0 || got.ArgonMemory == 0 || got.ArgonThreads == 0 {
			t.Fatalf("accepted zero parameters: %+v", got)
		}
	})
}

func BenchmarkScramHandshake(b *testing.B) {
	const user, pw = "bench", "SecurePassword123"
	cred, err := DeriveCredential(user, pw, make([]byte, 16), testArgonTime, testArgonMemory, testArgonThreads)
	if err != nil {
		b.Fatal(err)
	}
	s := NewScramServer()
	defer s.Stop()
	s.AddCredential(cred)

	for b.Loop() {
		c := NewScramClient(user, pw)
		first, err := c.StartAuthentication()
		if err != nil {
			b.Fatal(err)
		}
		serverFirst, err := s.ProcessClientFirstMessage(first.Username, first.ClientNonce)
		if err != nil {
			b.Fatal(err)
		}
		final, err := c.ProcessServerFirstMessage(serverFirst)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof); err != nil {
			b.Fatal(err)
		}
	}
}
