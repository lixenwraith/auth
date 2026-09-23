package auth

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestArgonExecutionBounds(t *testing.T) {
	for _, tc := range []struct {
		memory, time uint32
		threads      uint8
		want         error
	}{
		{1, 1, 1, ErrArgonInvalidParams},
		{MaxVerifyArgonMemory + 1, 1, 1, ErrPHCCostTooHigh},
		{testArgonMemory, MaxVerifyArgonTime + 1, 1, ErrPHCCostTooHigh},
		{testArgonMemory, 1, MaxVerifyArgonThreads + 1, ErrPHCCostTooHigh},
		{MaxVerifyArgonMemory, MaxVerifyArgonTime, 1, ErrPHCCostTooHigh},
		{math.MaxUint32, math.MaxUint32, math.MaxUint8, ErrPHCCostTooHigh},
	} {
		_, err := HashPassword("password123", WithMemory(tc.memory), WithTime(tc.time), WithThreads(tc.threads))
		errIs(t, err, tc.want, "hash bounds")
		_, err = DeriveCredential("u", "password123", make([]byte, 16), tc.time, tc.memory, tc.threads)
		if tc.want == ErrArgonInvalidParams {
			errIs(t, err, ErrSCRAMZeroParams, "derive invalid")
		} else {
			errIs(t, err, ErrSCRAMParamsTooLarge, "derive bounds")
		}
	}
	_, err := DeriveCredential("u", "password123", make([]byte, MaxArgonSaltLen+1), 1, 8, 1)
	errIs(t, err, ErrSCRAMSaltTooLong, "derive salt bound")
}

func TestNewCredentialAndOwnership(t *testing.T) {
	cred, err := NewCredential("u", "password123", cheapArgon...)
	noErr(t, err, "new")
	noErr(t, cred.Validate(), "validate")
	s := newTestServer(t)
	noErr(t, s.AddCredential(cred), "add")
	// Mutation after registration cannot change the server's credential.
	clear(cred.Salt)
	clear(cred.StoredKey)
	clear(cred.ServerKey)
	cred.Username = "changed"
	noErr(t, runHandshake(s, newTestScramClient("u", "password123")), "owned credential")

	salt := bytes.Repeat([]byte{1}, 16)
	derived, err := DeriveCredential("u", "password123", salt, 1, testArgonMemory, 1)
	noErr(t, err, "derive")
	clear(salt)
	if bytes.Equal(derived.Salt, salt) {
		t.Fatal("derived credential aliases salt")
	}
	_, err = NewCredential("u", "short", cheapArgon...)
	errIs(t, err, ErrWeakPassword, "new credential password policy")
}

func TestCredentialImportNumericTypes(t *testing.T) {
	cred, err := NewCredential("u", "password123", cheapArgon...)
	noErr(t, err, "new")
	for _, values := range [][3]any{
		{int64(1), int64(testArgonMemory), int64(1)},
		{uint64(1), uint64(testArgonMemory), uint64(1)},
		{json.Number("1"), json.Number("8192"), json.Number("1")},
	} {
		m := cred.Export()
		m["argon_time"], m["argon_memory"], m["argon_threads"] = values[0], values[1], values[2]
		_, err := ImportCredential(m)
		noErr(t, err, "import numeric types")
	}
	for _, bad := range []any{math.NaN(), math.Inf(1), math.Inf(-1), json.Number("1.5"), uint64(math.MaxUint64), int64(-1)} {
		for _, field := range []string{"argon_time", "argon_memory", "argon_threads"} {
			m := cred.Export()
			m[field] = bad
			_, err := ImportCredential(m)
			errIs(t, err, ErrCredInvalidType, "invalid number")
		}
	}
	for _, field := range []string{"salt", "stored_key", "server_key"} {
		m := cred.Export()
		m[field] = strings.Repeat("A", 10000)
		_, err := ImportCredential(m)
		hasErr(t, err, "oversized encoded field")
	}
}

func TestScramRegistrationRevocationAndStop(t *testing.T) {
	s, user, pw, cred := setupScram(t)
	errIs(t, s.AddCredential(nil), ErrInvalidCredentials, "nil credential")
	bad := *cred
	bad.StoredKey = nil
	errIs(t, s.AddCredential(&bad), ErrCredInvalidStoredKey, "missing stored key")
	bad = *cred
	bad.ArgonTime++
	errIs(t, s.AddCredential(&bad), ErrSCRAMCredentialProfile, "mixed profile")
	final := startHandshake(t, s, user, pw)
	noErr(t, s.AddCredential(cred), "replace")
	_, err := s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	errIs(t, err, ErrSCRAMInvalidNonce, "replacement invalidates pending proof")
	final = startHandshake(t, s, user, pw)
	s.RemoveCredential(user)
	_, err = s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	errIs(t, err, ErrSCRAMInvalidNonce, "removal invalidates pending proof")
	errIs(t, runHandshake(s, newTestScramClient(user, pw)), ErrInvalidCredentials, "removed user")
	noErr(t, s.AddCredential(cred), "restore")
	final = startHandshake(t, s, user, pw)
	s.Stop()
	eq(t, handshakeCount(s), 0, "stop discards pending work")
	_, err = s.ProcessClientFirstMessage(user, "nonce")
	errIs(t, err, ErrSCRAMStopped, "first after stop")
	_, err = s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
	errIs(t, err, ErrSCRAMStopped, "final after stop")
	errIs(t, s.AddCredential(cred), ErrSCRAMStopped, "register after stop")
}

func TestScramStableDecoyKey(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	a, err := NewScramServerWithDecoyKey(key)
	noErr(t, err, "server a")
	defer a.Stop()
	b, err := NewScramServerWithDecoyKey(key)
	noErr(t, err, "server b")
	defer b.Stop()
	clear(key)
	first, err := a.ProcessClientFirstMessage("unknown", "a")
	noErr(t, err, "first a")
	second, err := b.ProcessClientFirstMessage("unknown", "b")
	noErr(t, err, "first b")
	eq(t, first.Salt, second.Salt, "stable salt across instances")
	_, err = NewScramServerWithDecoyKey(make([]byte, 31))
	errIs(t, err, ErrSCRAMDecoyKey, "short key")
}

func TestScramInputBounds(t *testing.T) {
	s := newTestServer(t)
	for _, user := range []string{"", "a,b", "a=b", "a\x00b", string([]byte{0xff}), strings.Repeat("a", MaxUsernameLen+1)} {
		_, err := s.ProcessClientFirstMessage(user, "n")
		errIs(t, err, ErrSCRAMInvalidUsername, "username")
		_, err = newTestScramClient(user, "password123").StartAuthentication()
		errIs(t, err, ErrSCRAMInvalidUsername, "client username")
	}
	for _, nonce := range []string{"", "a,b", "a\nb", "a b", strings.Repeat("x", MaxClientNonceLen+1)} {
		_, err := s.ProcessClientFirstMessage("u", nonce)
		errIs(t, err, ErrSCRAMInvalidNonce, "nonce")
	}
	eq(t, handshakeCount(s), 0, "invalid input creates no state")
	c := newTestScramClient("u", "password123")
	first, err := c.StartAuthentication()
	noErr(t, err, "start")
	challenge, err := s.ProcessClientFirstMessage(first.Username, first.ClientNonce)
	noErr(t, err, "challenge")
	c.Password = strings.Repeat("x", MaxPasswordLen+1)
	_, err = c.ProcessServerFirstMessage(challenge)
	errIs(t, err, ErrPasswordTooLong, "mutable password rechecked")
}

func TestScramConcurrentProofConsumedOnce(t *testing.T) {
	s, user, pw, _ := setupScram(t)
	final := startHandshake(t, s, user, pw)
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 64 {
		wg.Go(func() {
			<-start
			_, err := s.ProcessClientFinalMessage(final.FullNonce, final.ClientProof)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrSCRAMVerifyInProgress) && !errors.Is(err, ErrSCRAMInvalidNonce) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	eq(t, successes.Load(), int32(1), "only one proof may succeed")
	eq(t, handshakeCount(s), 0, "consumed proof")
}

func TestJWTConfigurationOwnership(t *testing.T) {
	secret := bytes.Clone(testSecret)
	audience := []string{"vif"}
	j, err := NewJWT(secret, WithIssuer("issuer"), WithAudience(audience))
	noErr(t, err, "new")
	clear(secret)
	audience[0] = "logwisp"
	token, err := j.GenerateToken("u", nil)
	noErr(t, err, "sign")
	check, err := NewJWT(testSecret, WithIssuer("issuer"), WithAudience([]string{"vif"}))
	noErr(t, err, "check")
	_, _, err = check.ValidateToken(token)
	noErr(t, err, "owned config")
	_, _, err = j.ValidateToken(token)
	noErr(t, err, "cached parser")
	other, err := NewJWT(testSecret, WithIssuer("issuer"), WithAudience([]string{"logwisp"}))
	noErr(t, err, "other service")
	_, _, err = other.ValidateToken(token)
	errIs(t, err, ErrTokenMissingClaim, "cross-service token")
}

func TestJWTBoundedCanonicalEncoding(t *testing.T) {
	j, err := NewJWT(testSecret)
	noErr(t, err, "new")
	token, err := j.GenerateToken("u", nil)
	noErr(t, err, "sign")
	// A 32-byte signature has two unused bits in its last base64url character.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, token[len(token)-1])
	malleated := token[:len(token)-1] + string(alphabet[last+1])
	for _, bad := range []string{token + "\n", malleated, strings.Repeat("x", MaxTokenLen+1)} {
		_, _, err = j.ValidateToken(bad)
		hasErr(t, err, "malformed/oversized token")
		_, _, err = ValidateHS256Token(testSecret, bad)
		hasErr(t, err, "standalone malformed/oversized")
	}
	header := defaultHeader()
	header["crit"] = []string{"custom"}
	critical := signHS256(t, testSecret, header, map[string]any{"sub": "u", "exp": time.Now().Add(time.Hour).Unix()})
	_, _, err = j.ValidateToken(critical)
	hasErr(t, err, "unsupported critical extension")
	_, err = j.GenerateToken("u", map[string]any{"huge": strings.Repeat("x", MaxTokenLen)})
	errIs(t, err, ErrTokenTooLong, "oversized generated JWT")
}

func TestRSAValidationAndOwnership(t *testing.T) {
	for _, key := range []*rsa.PublicKey{{}, {N: big.NewInt(3), E: 65537}, {N: testRSAKey().N, E: 2}} {
		_, err := NewJWTVerifier(key)
		hasErr(t, err, "invalid/weak public key")
	}
	for _, key := range []*rsa.PrivateKey{{}, {PublicKey: testRSAKey().PublicKey}, {PublicKey: testRSAKey().PublicKey, D: big.NewInt(1), Primes: []*big.Int{nil, nil}}} {
		_, err := NewJWTRSA(key)
		hasErr(t, err, "invalid private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(testRSAKey()))
	noErr(t, err, "copy")
	signer, err := NewJWTRSA(key)
	noErr(t, err, "signer")
	verifier, err := NewJWTVerifier(&key.PublicKey)
	noErr(t, err, "verifier")
	key.N.SetInt64(3)
	key.D.SetInt64(0)
	key.Primes[0].SetInt64(0)
	token, err := signer.GenerateToken("u", nil)
	noErr(t, err, "sign with copied key")
	_, _, err = verifier.ValidateToken(token)
	noErr(t, err, "verify with copied key")
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&testRSAKey().PublicKey)})
	fromPEM, err := NewJWTVerifierFromPEM(pkcs1)
	noErr(t, err, "PKCS1 public PEM")
	_, _, err = fromPEM.ValidateToken(token)
	noErr(t, err, "PEM verifier")
}

func TestSimpleTokenZeroValueAndBounds(t *testing.T) {
	var v SimpleTokenValidator
	v.AddToken("")
	v.AddToken(strings.Repeat("x", MaxTokenLen+1))
	if v.ValidateToken("") || v.ValidateToken(strings.Repeat("x", MaxTokenLen+1)) {
		t.Fatal("invalid credential accepted")
	}
	v.AddToken("a-token")
	isTrue(t, v.ValidateToken("a-token"), "zero value initialized")
	v.RemoveToken("a-token")
	isTrue(t, !v.ValidateToken("a-token"), "revoked")
}

func BenchmarkCredentialProvisioning(b *testing.B) {
	b.Run("direct", func(b *testing.B) {
		for b.Loop() {
			if _, err := NewCredential("u", "password123", cheapArgon...); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("via_phc", func(b *testing.B) {
		for b.Loop() {
			hash, err := HashPassword("password123", cheapArgon...)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := MigrateFromPHC("u", "password123", hash); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestScramClientRejectsKDFDowngrade(t *testing.T) {
	c := NewScramClient("u", "password123")
	first, err := c.StartAuthentication()
	noErr(t, err, "start")
	msg := ServerFirstMessage{
		FullNonce: first.ClientNonce + "server", Salt: "AAAAAAAAAAAAAAAAAAAAAA==",
		ArgonTime: 1, ArgonMemory: 8, ArgonThreads: 1,
	}
	_, err = c.ProcessServerFirstMessage(msg)
	errIs(t, err, ErrSCRAMParamsTooSmall, "hostile KDF downgrade")
	for _, option := range []ScramClientOption{WithMinArgonCost(0, 8), WithMinArgonCost(1, 0), WithMinArgonCost(1, MaxVerifyArgonMemory+1)} {
		_, err := NewScramClient("u", "password123", option).StartAuthentication()
		hasErr(t, err, "invalid client policy")
	}
}
