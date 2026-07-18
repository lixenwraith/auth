package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

// Assertion helpers. Failures are fatal: most tests below are sequential
// protocol exchanges where continuing past a failure only produces noise.

func noErr(t *testing.T, err error, ctx string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", ctx, err)
	}
}

func hasErr(t *testing.T, err error, ctx string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error, got nil", ctx)
	}
}

func errIs(t *testing.T, err, target error, ctx string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want %v", ctx, err, target)
	}
}

func eq[T comparable](t *testing.T, got, want T, ctx string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", ctx, got, want)
	}
}

func eqBytes(t *testing.T, got, want []byte, ctx string) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: got %x, want %x", ctx, got, want)
	}
}

func isTrue(t *testing.T, v bool, ctx string) {
	t.Helper()
	if !v {
		t.Fatalf("%s: got false, want true", ctx)
	}
}

// Test KDF cost. Parameter handling is verified independently of parameter
// magnitude, so every test that does not measure defaults uses these.
const (
	testArgonTime    = 1
	testArgonMemory  = 8 * 1024
	testArgonThreads = 1
)

var cheapArgon = []Option{
	WithTime(testArgonTime),
	WithMemory(testArgonMemory),
	WithThreads(testArgonThreads),
}

// rawB64 encodes n zero bytes in the PHC alphabet.
func rawB64(n int) string {
	return base64.RawStdEncoding.EncodeToString(make([]byte, n))
}

// phcFor builds a PHC record with an arbitrary salt and digest length, which
// HashPassword cannot produce.
func phcFor(password string, salt []byte, keyLen uint32) string {
	digest := argon2.IDKey([]byte(password), salt, testArgonTime, testArgonMemory, testArgonThreads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, testArgonMemory, testArgonTime, testArgonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest))
}
