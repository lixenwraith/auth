package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testSecret = []byte("test-secret-key-must-be-32-bytes")

func genRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

// RSA key generation is the dominant cost in this file; amortize it.
var (
	testRSAKey    = sync.OnceValue(genRSAKey)
	testRSAKeyAlt = sync.OnceValue(genRSAKey)
)

func defaultHeader() map[string]any { return map[string]any{"alg": "HS256", "typ": "JWT"} }

// signHS256 assembles a token from raw maps, bypassing the package so that
// malformed and hostile tokens can be constructed.
func signHS256(t *testing.T, secret []byte, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	noErr(t, err, "marshal header")
	c, err := json.Marshal(claims)
	noErr(t, err, "marshal claims")

	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func unsignedToken(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	noErr(t, err, "marshal header")
	c, err := json.Marshal(claims)
	noErr(t, err, "marshal claims")
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c) + "."
}

func decodeSegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	noErr(t, err, "segment decode")
	var m map[string]any
	noErr(t, json.Unmarshal(raw, &m), "segment unmarshal")
	return m
}

func jwtParts(t *testing.T, token string) (header, payload map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	eq(t, len(parts), 3, "token segments")
	return decodeSegment(t, parts[0]), decodeSegment(t, parts[1])
}

func str(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("claim %q: %v is not a string", key, m[key])
	}
	return v
}

func num(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("claim %q: %v is not a number", key, m[key])
	}
	return v
}

func TestJWTHS256RoundTrip(t *testing.T) {
	manager, err := NewJWT(testSecret)
	noErr(t, err, "NewJWT")

	token, err := manager.GenerateToken("user123", map[string]any{
		"email": "test@example.com",
		"role":  "admin",
	})
	noErr(t, err, "GenerateToken")

	header, payload := jwtParts(t, token)
	eq(t, str(t, header, "alg"), "HS256", "alg")
	eq(t, str(t, header, "typ"), "JWT", "typ")
	eq(t, str(t, payload, "sub"), "user123", "subject")

	exp, iat, nbf := num(t, payload, "exp"), num(t, payload, "iat"), num(t, payload, "nbf")
	eq(t, int64(exp-iat), int64(DefaultTokenLifetime/time.Second), "default lifetime")
	eq(t, nbf, iat, "nbf equals iat")
	if _, present := payload["iss"]; present {
		t.Fatal("issuer emitted without configuration")
	}

	userID, claims, err := manager.ValidateToken(token)
	noErr(t, err, "ValidateToken")
	eq(t, userID, "user123", "user id")
	eq(t, len(claims), 2, "claim count")
	eq(t, str(t, claims, "email"), "test@example.com", "email claim")
	eq(t, str(t, claims, "role"), "admin", "role claim")

	// nil claims must not emit an extra object
	bare, err := manager.GenerateToken("user123", nil)
	noErr(t, err, "GenerateToken without claims")
	_, barePayload := jwtParts(t, bare)
	if _, present := barePayload["extra"]; present {
		t.Fatal("empty extra claim emitted")
	}
	_, claims, err = manager.ValidateToken(bare)
	noErr(t, err, "ValidateToken without claims")
	eq(t, len(claims), 0, "no extra claims")
}

func TestJWTSecretLength(t *testing.T) {
	_, err := NewJWT(nil)
	errIs(t, err, ErrSecretTooShort, "nil secret")
	_, err = NewJWT(make([]byte, 31))
	errIs(t, err, ErrSecretTooShort, "31 bytes")
	_, err = NewJWT(make([]byte, 32))
	noErr(t, err, "32 bytes")

	_, err = GenerateHS256Token(make([]byte, 31), "u", nil, time.Hour)
	errIs(t, err, ErrSecretTooShort, "standalone generate")
	_, _, err = ValidateHS256Token(make([]byte, 31), "irrelevant")
	errIs(t, err, ErrSecretTooShort, "standalone validate")
}

func TestJWTEmptyUserID(t *testing.T) {
	manager, err := NewJWT(testSecret)
	noErr(t, err, "NewJWT")
	_, err = manager.GenerateToken("", map[string]any{"role": "admin"})
	errIs(t, err, ErrTokenEmptyUserID, "empty user id")
	_, err = GenerateHS256Token(testSecret, "", nil, time.Hour)
	errIs(t, err, ErrTokenEmptyUserID, "standalone empty user id")
}

func TestJWTRS256(t *testing.T) {
	key := testRSAKey()

	signer, err := NewJWTRSA(key)
	noErr(t, err, "NewJWTRSA")
	token, err := signer.GenerateToken("user456", map[string]any{"scope": "read:all"})
	noErr(t, err, "GenerateToken")

	header, _ := jwtParts(t, token)
	eq(t, str(t, header, "alg"), "RS256", "alg")

	userID, claims, err := signer.ValidateToken(token)
	noErr(t, err, "self validation")
	eq(t, userID, "user456", "user id")
	eq(t, str(t, claims, "scope"), "read:all", "scope claim")

	verifier, err := NewJWTVerifier(&key.PublicKey)
	noErr(t, err, "NewJWTVerifier")
	userID, _, err = verifier.ValidateToken(token)
	noErr(t, err, "verifier validation")
	eq(t, userID, "user456", "user id from verifier")

	_, err = verifier.GenerateToken("user456", nil)
	errIs(t, err, ErrTokenNoPrivateKey, "verifier must not sign")

	// an unrelated key must not verify
	foreign, err := NewJWTVerifier(&testRSAKeyAlt().PublicKey)
	noErr(t, err, "NewJWTVerifier foreign")
	_, _, err = foreign.ValidateToken(token)
	errIs(t, err, ErrTokenInvalidSignature, "foreign public key")

	_, err = NewJWTRSA(nil)
	errIs(t, err, ErrTokenNoPrivateKey, "nil private key")
	_, err = NewJWTVerifier(nil)
	errIs(t, err, ErrTokenNoPublicKey, "nil public key")
}

func TestJWTAlgorithmEnforcement(t *testing.T) {
	key := testRSAKey()
	hs, err := NewJWT(testSecret)
	noErr(t, err, "NewJWT")
	rs, err := NewJWTRSA(key)
	noErr(t, err, "NewJWTRSA")

	hsToken, err := hs.GenerateToken("u", nil)
	noErr(t, err, "HS256 token")
	rsToken, err := rs.GenerateToken("u", nil)
	noErr(t, err, "RS256 token")

	_, _, err = hs.ValidateToken(rsToken)
	errIs(t, err, ErrTokenInvalidSignature, "RS256 token to HS256 manager")
	_, _, err = rs.ValidateToken(hsToken)
	errIs(t, err, ErrTokenInvalidSignature, "HS256 token to RS256 manager")

	// ☢ algorithm confusion: HS256 token keyed with the RSA public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	noErr(t, err, "marshal public key")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	forged := signHS256(t, pubPEM, defaultHeader(), map[string]any{
		"sub": "attacker", "exp": time.Now().Add(time.Hour).Unix(),
	})
	_, _, err = rs.ValidateToken(forged)
	errIs(t, err, ErrTokenInvalidSignature, "algorithm confusion")

	// alg: none
	none := unsignedToken(t, map[string]any{"alg": "none", "typ": "JWT"}, map[string]any{
		"sub": "attacker", "exp": time.Now().Add(time.Hour).Unix(),
	})
	_, _, err = hs.ValidateToken(none)
	errIs(t, err, ErrTokenInvalidSignature, "alg none against HS256")
	_, _, err = rs.ValidateToken(none)
	errIs(t, err, ErrTokenInvalidSignature, "alg none against RS256")

	// an unregistered algorithm is unverifiable, mapped to malformed
	unknown := signHS256(t, testSecret, map[string]any{"alg": "HS999", "typ": "JWT"}, map[string]any{
		"sub": "attacker", "exp": time.Now().Add(time.Hour).Unix(),
	})
	_, _, err = hs.ValidateToken(unknown)
	errIs(t, err, ErrTokenMalformed, "unknown algorithm")
}

func TestJWTTampering(t *testing.T) {
	manager, err := NewJWT(testSecret)
	noErr(t, err, "NewJWT")
	token, err := manager.GenerateToken("user1", map[string]any{"role": "user"})
	noErr(t, err, "GenerateToken")
	parts := strings.Split(token, ".")

	escalated, err := json.Marshal(map[string]any{
		"sub": "user1", "exp": time.Now().Add(time.Hour).Unix(),
		"extra": map[string]any{"role": "admin"},
	})
	noErr(t, err, "marshal forged claims")

	// length-preserving corruption, so the segment still decodes and
	// the failure is attributable to the MAC rather than the encoding
	corrupt := []byte(parts[2])
	if corrupt[0] == 'A' {
		corrupt[0] = 'B'
	} else {
		corrupt[0] = 'A'
	}

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"payload rewrite", parts[0] + "." + base64.RawURLEncoding.EncodeToString(escalated) + "." + parts[2], ErrTokenInvalidSignature},
		{"corrupt signature", parts[0] + "." + parts[1] + "." + string(corrupt), ErrTokenInvalidSignature},
		{"truncated signature", parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-2], ErrTokenMalformed},
		{"replaced signature", parts[0] + "." + parts[1] + ".invalidsignature", ErrTokenInvalidSignature},
		{"empty", "", ErrTokenMalformed},
		{"two segments", parts[0] + "." + parts[1], ErrTokenMalformed},
		{"four segments", token + ".extra", ErrTokenMalformed},
		{"separators only", "..", ErrTokenMalformed},
		{"payload not base64", parts[0] + ".!!!." + parts[2], ErrTokenMalformed},
		{"header not base64", "!!!." + parts[1] + "." + parts[2], ErrTokenMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userID, claims, err := manager.ValidateToken(tc.token)
			errIs(t, err, tc.want, tc.name)
			eq(t, userID, "", "user id on failure")
			if claims != nil {
				t.Fatalf("%s: claims returned on failure", tc.name)
			}
		})
	}
}

func TestJWTExpiryAndLeeway(t *testing.T) {
	now := time.Now()
	strict, err := NewJWT(testSecret, WithLeeway(0))
	noErr(t, err, "NewJWT strict")
	lenient, err := NewJWT(testSecret, WithLeeway(5*time.Minute))
	noErr(t, err, "NewJWT lenient")

	expired := signHS256(t, testSecret, defaultHeader(), map[string]any{
		"sub": "u", "iat": now.Add(-2 * time.Hour).Unix(), "exp": now.Add(-time.Minute).Unix(),
	})
	_, _, err = strict.ValidateToken(expired)
	errIs(t, err, ErrTokenExpired, "expired token")
	_, _, err = lenient.ValidateToken(expired)
	noErr(t, err, "expiry inside leeway")

	notYet := signHS256(t, testSecret, defaultHeader(), map[string]any{
		"sub": "u", "nbf": now.Add(2 * time.Second).Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	_, _, err = strict.ValidateToken(notYet)
	errIs(t, err, ErrTokenNotYetValid, "nbf in the future")
	_, _, err = lenient.ValidateToken(notYet)
	noErr(t, err, "nbf inside leeway")

	// exp is mandatory. ‼️ mapJWTError has no case for
	// jwt.ErrTokenRequiredClaimMissing, so this surfaces as malformed.
	noExp := signHS256(t, testSecret, defaultHeader(), map[string]any{"sub": "u", "iat": now.Unix()})
	_, _, err = strict.ValidateToken(noExp)
	errIs(t, err, ErrTokenMissingClaim, "missing exp")

	// generated lifetimes are honored without waiting for them
	short, err := NewJWT(testSecret, WithTokenLifetime(time.Second))
	noErr(t, err, "NewJWT short lifetime")
	token, err := short.GenerateToken("u", nil)
	noErr(t, err, "GenerateToken")
	_, payload := jwtParts(t, token)
	eq(t, int64(num(t, payload, "exp")-num(t, payload, "iat")), int64(1), "encoded lifetime")
	_, _, err = short.ValidateToken(token)
	noErr(t, err, "valid immediately")
}

func TestJWTIssuerAudience(t *testing.T) {
	manager, err := NewJWT(testSecret,
		WithTokenLifetime(time.Hour),
		WithIssuer("test-issuer"),
		WithAudience([]string{"api.example.com"}),
	)
	noErr(t, err, "NewJWT")

	token, err := manager.GenerateToken("user1", nil)
	noErr(t, err, "GenerateToken")

	_, payload := jwtParts(t, token)
	eq(t, str(t, payload, "iss"), "test-issuer", "issuer")
	audience, ok := payload["aud"].([]any)
	isTrue(t, ok, "audience encoded as an array")
	eq(t, len(audience), 1, "audience length")
	eq(t, audience[0], any("api.example.com"), "audience value")
	eq(t, int64(num(t, payload, "exp")-num(t, payload, "iat")), int64(3600), "custom lifetime")

	_, _, err = manager.ValidateToken(token)
	noErr(t, err, "self-issued token")

	other, err := NewJWT(testSecret, WithTokenLifetime(time.Hour), WithIssuer("other-issuer"))
	noErr(t, err, "NewJWT other issuer")
	otherToken, err := other.GenerateToken("user1", nil)
	noErr(t, err, "GenerateToken other issuer")
	_, _, err = manager.ValidateToken(otherToken)
	errIs(t, err, ErrTokenMissingClaim, "issuer mismatch")

	missingAudience := signHS256(t, testSecret, defaultHeader(), map[string]any{
		"sub": "u", "iss": "test-issuer", "exp": time.Now().Add(time.Hour).Unix(),
	})
	_, _, err = manager.ValidateToken(missingAudience)
	errIs(t, err, ErrTokenMissingClaim, "absent audience is rejected when expected")

	superset := signHS256(t, testSecret, defaultHeader(), map[string]any{
		"sub": "u", "iss": "test-issuer", "exp": time.Now().Add(time.Hour).Unix(),
		"aud": []string{"other.example.com", "api.example.com"},
	})
	_, _, err = manager.ValidateToken(superset)
	noErr(t, err, "expected audience among others")

	// an unconstrained manager imposes neither claim
	plain, err := NewJWT(testSecret)
	noErr(t, err, "NewJWT plain")
	_, _, err = plain.ValidateToken(token)
	noErr(t, err, "unconstrained validation")
}

func TestJWTUnenforcedClaims(t *testing.T) {
	// Documented gaps: sub is not required and iat is not verified.
	// Callers must reject an empty user id themselves.
	manager, err := NewJWT(testSecret)
	noErr(t, err, "NewJWT")

	token := signHS256(t, testSecret, defaultHeader(), map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(24 * time.Hour).Unix(),
	})
	userID, claims, err := manager.ValidateToken(token)
	noErr(t, err, "token without subject")
	eq(t, userID, "", "empty subject accepted")
	eq(t, len(claims), 0, "no extra claims")
}

func TestJWTOptionGuards(t *testing.T) {
	manager, err := NewJWT(testSecret,
		WithTokenLifetime(0), WithTokenLifetime(-time.Hour), WithLeeway(-time.Second))
	noErr(t, err, "NewJWT")
	eq(t, manager.tokenLifetime, DefaultTokenLifetime, "lifetime unchanged")
	eq(t, manager.leeway, DefaultLeeway, "leeway unchanged")

	manager, err = NewJWT(testSecret, WithLeeway(0))
	noErr(t, err, "NewJWT zero leeway")
	eq(t, manager.leeway, time.Duration(0), "zero leeway applied")

	// options apply to every constructor
	verifier, err := NewJWTVerifier(&testRSAKey().PublicKey, WithIssuer("iss"), WithLeeway(time.Minute))
	noErr(t, err, "NewJWTVerifier")
	eq(t, verifier.issuer, "iss", "issuer")
	eq(t, verifier.leeway, time.Minute, "leeway")
}

func TestJWTStandaloneFunctions(t *testing.T) {
	token, err := GenerateHS256Token(testSecret, "standalone-user",
		map[string]any{"test": "value", "count": 42}, time.Hour)
	noErr(t, err, "GenerateHS256Token")

	userID, claims, err := ValidateHS256Token(testSecret, token)
	noErr(t, err, "ValidateHS256Token")
	eq(t, userID, "standalone-user", "user id")
	eq(t, str(t, claims, "test"), "value", "string claim")
	eq(t, claims["count"], any(float64(42)), "numeric claim after JSON round trip")

	_, _, err = ValidateHS256Token(bytes.Repeat([]byte("x"), 32), token)
	errIs(t, err, ErrTokenInvalidSignature, "wrong secret")

	expired, err := GenerateHS256Token(testSecret, "u", nil, -time.Hour)
	noErr(t, err, "expired token")
	_, _, err = ValidateHS256Token(testSecret, expired)
	errIs(t, err, ErrTokenExpired, "expired beyond default leeway")

	// standalone validation checks neither issuer nor audience
	scoped, err := NewJWT(testSecret, WithIssuer("iss"), WithAudience([]string{"aud"}))
	noErr(t, err, "NewJWT scoped")
	scopedToken, err := scoped.GenerateToken("u", nil)
	noErr(t, err, "GenerateToken scoped")
	_, _, err = ValidateHS256Token(testSecret, scopedToken)
	noErr(t, err, "issuer and audience are not enforced standalone")

	// tokens are interchangeable with the manager form
	managed, err := NewJWT(testSecret)
	noErr(t, err, "NewJWT")
	_, _, err = managed.ValidateToken(token)
	noErr(t, err, "standalone token accepted by manager")
}

func TestJWTPEM(t *testing.T) {
	key := testRSAKey()

	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	noErr(t, err, "marshal pkcs8")
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	pkixBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	noErr(t, err, "marshal pkix")
	pkix := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixBytes})

	for name, blob := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		t.Run(name, func(t *testing.T) {
			signer, err := NewJWTRSAFromPEM(blob, WithTokenLifetime(time.Hour))
			noErr(t, err, "NewJWTRSAFromPEM")
			eq(t, signer.tokenLifetime, time.Hour, "options forwarded")

			token, err := signer.GenerateToken("user-from-pem", nil)
			noErr(t, err, "GenerateToken")

			verifier, err := NewJWTVerifierFromPEM(pkix)
			noErr(t, err, "NewJWTVerifierFromPEM")
			userID, _, err := verifier.ValidateToken(token)
			noErr(t, err, "ValidateToken")
			eq(t, userID, "user-from-pem", "user id")
		})
	}

	_, err = NewJWTRSAFromPEM([]byte("invalid pem data"))
	errIs(t, err, ErrRSAInvalidPEM, "private: not pem")
	_, err = NewJWTRSAFromPEM(nil)
	errIs(t, err, ErrRSAInvalidPEM, "private: empty")
	_, err = NewJWTVerifierFromPEM([]byte("invalid pem data"))
	errIs(t, err, ErrRSAInvalidPEM, "public: not pem")

	_, err = NewJWTRSAFromPEM(pkix)
	errIs(t, err, ErrRSAInvalidPrivateKey, "public key supplied as private")
	_, err = NewJWTVerifierFromPEM(pkcs8)
	errIs(t, err, ErrRSAInvalidPublicKey, "private key supplied as public")

	// well-formed keys of the wrong algorithm
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	noErr(t, err, "ed25519 keygen")
	edPubBytes, err := x509.MarshalPKIXPublicKey(edPub)
	noErr(t, err, "marshal ed25519 public")
	_, err = NewJWTVerifierFromPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edPubBytes}))
	errIs(t, err, ErrRSANotPublicKey, "non-rsa public key")

	edPrivBytes, err := x509.MarshalPKCS8PrivateKey(edPriv)
	noErr(t, err, "marshal ed25519 private")
	_, err = NewJWTRSAFromPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edPrivBytes}))
	errIs(t, err, ErrRSAInvalidPrivateKey, "non-rsa private key")
}

func TestMapJWTError(t *testing.T) {
	cases := []struct {
		in   error
		want error
	}{
		{jwt.ErrTokenMalformed, ErrTokenMalformed},
		{jwt.ErrTokenUnverifiable, ErrTokenMalformed},
		{jwt.ErrTokenSignatureInvalid, ErrTokenInvalidSignature},
		{jwt.ErrTokenExpired, ErrTokenExpired},
		{jwt.ErrTokenNotValidYet, ErrTokenNotYetValid},
		{jwt.ErrTokenInvalidAudience, ErrTokenMissingClaim},
		{jwt.ErrTokenInvalidIssuer, ErrTokenMissingClaim},
		{jwt.ErrTokenRequiredClaimMissing, ErrTokenMissingClaim},
		{errors.New("unclassified"), ErrTokenMalformed},
	}
	for _, tc := range cases {
		got := mapJWTError(tc.in)
		errIs(t, got, tc.want, "mapped sentinel")
		errIs(t, got, tc.in, "original error preserved")
	}
}

func TestJWTConcurrency(t *testing.T) {
	manager, err := NewJWT(testSecret, WithTokenLifetime(time.Hour), WithIssuer("iss"))
	noErr(t, err, "NewJWT")
	shared, err := manager.GenerateToken("user1", map[string]any{"role": "admin"})
	noErr(t, err, "GenerateToken")

	const n = 32
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := manager.ValidateToken(shared); err != nil {
				errs <- err
				return
			}
			token, err := manager.GenerateToken(fmt.Sprintf("user-%d", i), map[string]any{"n": i})
			if err != nil {
				errs <- err
				return
			}
			if _, _, err := manager.ValidateToken(token); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent operation: %v", err)
	}
}

func FuzzValidateHS256Token(f *testing.F) {
	token, err := GenerateHS256Token(testSecret, "seed", map[string]any{"a": 1}, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token)
	f.Add("")
	f.Add("a.b.c")
	f.Add(strings.Repeat(".", 16))

	f.Fuzz(func(t *testing.T, s string) {
		_, _, err := ValidateHS256Token(testSecret, s)
		if err != nil {
			return
		}
		// acceptance implies a well-formed, correctly signed token
		parts := strings.Split(s, ".")
		if len(parts) != 3 {
			t.Fatalf("accepted token with %d segments", len(parts))
		}
		mac := hmac.New(sha256.New, testSecret)
		mac.Write([]byte(parts[0] + "." + parts[1]))
		sig, decErr := base64.RawURLEncoding.DecodeString(parts[2])
		if decErr != nil || !hmac.Equal(sig, mac.Sum(nil)) {
			t.Fatal("accepted token with an invalid signature")
		}
	})
}

func BenchmarkJWTHS256(b *testing.B) {
	manager, err := NewJWT(testSecret)
	if err != nil {
		b.Fatal(err)
	}
	claims := map[string]any{"role": "admin"}
	for b.Loop() {
		token, err := manager.GenerateToken("user1", claims)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := manager.ValidateToken(token); err != nil {
			b.Fatal(err)
		}
	}
}
