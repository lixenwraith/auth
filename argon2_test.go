package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashPasswordEncoding(t *testing.T) {
	const pw = "testPassword123"
	hash, err := HashPassword(pw)
	noErr(t, err, "HashPassword")

	parts := strings.Split(hash, "$")
	eq(t, len(parts), 6, "field count")
	eq(t, parts[0], "", "leading field")
	eq(t, parts[1], "argon2id", "algorithm")
	eq(t, parts[2], fmt.Sprintf("v=%d", argon2.Version), "version")
	eq(t, parts[3], fmt.Sprintf("m=%d,t=%d,p=%d", DefaultArgonMemory, DefaultArgonTime, DefaultArgonThreads), "parameters")

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	noErr(t, err, "salt decode")
	eq(t, len(salt), DefaultArgonSaltLen, "salt length")

	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	noErr(t, err, "digest decode")
	eq(t, len(digest), DefaultArgonKeyLen, "digest length")

	// the encoded digest must be reproducible from the encoded material
	want := argon2.IDKey([]byte(pw), salt, DefaultArgonTime, DefaultArgonMemory, DefaultArgonThreads, DefaultArgonKeyLen)
	eqBytes(t, digest, want, "digest")

	isTrue(t, len(hash) <= MaxPHCHashLen, "default encoding within MaxPHCHashLen")
	noErr(t, ValidatePHCHashFormat(hash), "self-validation")
}

func TestHashPasswordSaltUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for range 64 {
		h, err := HashPassword("testPassword123", cheapArgon...)
		noErr(t, err, "HashPassword")
		salt := strings.Split(h, "$")[4]
		if _, dup := seen[salt]; dup {
			t.Fatalf("duplicate salt: %s", salt)
		}
		seen[salt] = struct{}{}
	}
}

func TestVerifyPassword(t *testing.T) {
	const pw = "testPassword123"
	hash, err := HashPassword(pw, cheapArgon...)
	noErr(t, err, "HashPassword")

	noErr(t, VerifyPassword(pw, hash), "correct password")
	noErr(t, VerifyPassword(pw, hash), "repeat verification")

	for _, wrong := range []string{"wrongPassword", "", pw + "\x00", pw + " ", strings.ToUpper(pw)} {
		errIs(t, VerifyPassword(wrong, hash), ErrInvalidCredentials, fmt.Sprintf("password %q", wrong))
	}

	// verification has no minimum length: legacy hashes must stay verifiable
	weak := phcFor("short", []byte("0123456789abcdef"), DefaultArgonKeyLen)
	noErr(t, VerifyPassword("short", weak), "sub-minimum password verifies")
}

func TestPasswordLengthBounds(t *testing.T) {
	_, err := HashPassword("")
	errIs(t, err, ErrWeakPassword, "empty")
	_, err = HashPassword("1234567")
	errIs(t, err, ErrWeakPassword, "seven bytes")

	h8, err := HashPassword("12345678", cheapArgon...)
	noErr(t, err, "eight bytes")
	noErr(t, VerifyPassword("12345678", h8), "verify eight bytes")

	// the minimum is measured in bytes, not runes
	const multibyte = "ünïcödé"
	eq(t, len([]rune(multibyte)), 7, "rune count")
	eq(t, len(multibyte), 11, "byte count")
	hm, err := HashPassword(multibyte, cheapArgon...)
	noErr(t, err, "multibyte password")
	noErr(t, VerifyPassword(multibyte, hm), "verify multibyte")

	maxPw := strings.Repeat("a", MaxPasswordLen)
	hMax, err := HashPassword(maxPw, cheapArgon...)
	noErr(t, err, "maximum length")
	noErr(t, VerifyPassword(maxPw, hMax), "verify maximum length")

	_, err = HashPassword(maxPw+"a", cheapArgon...)
	errIs(t, err, ErrPasswordTooLong, "over maximum")
	// rejected before the KDF runs
	errIs(t, VerifyPassword(maxPw+"a", hMax), ErrPasswordTooLong, "verify over maximum")
}

func TestHashPasswordOptions(t *testing.T) {
	const pw = "testPassword123"

	h, err := HashPassword(pw, WithTime(2), WithMemory(16*1024), WithThreads(2))
	noErr(t, err, "custom parameters")
	eq(t, strings.Split(h, "$")[3], "m=16384,t=2,p=2", "encoded parameters")
	noErr(t, VerifyPassword(pw, h), "verify custom parameters")

	// zero values are discarded by the option guards
	h, err = HashPassword(pw, WithMemory(testArgonMemory), WithTime(0), WithThreads(0))
	noErr(t, err, "zero-valued options")
	eq(t, strings.Split(h, "$")[3],
		fmt.Sprintf("m=%d,t=%d,p=%d", testArgonMemory, DefaultArgonTime, DefaultArgonThreads),
		"defaults retained")

	// the last option wins
	h, err = HashPassword(pw, WithMemory(64*1024), WithMemory(testArgonMemory), WithTime(1), WithThreads(1))
	noErr(t, err, "repeated option")
	eq(t, strings.Split(h, "$")[3], fmt.Sprintf("m=%d,t=1,p=1", testArgonMemory), "last option applied")
}

func TestVerifyPasswordNonStandardDigestLength(t *testing.T) {
	// Records produced elsewhere may encode digests other than 32 bytes;
	// verification must derive at the encoded length.
	const pw = "testPassword123"
	salt := []byte("0123456789abcdef0123")

	for _, keyLen := range []uint32{16, 20, 32, MaxArgonKeyLen} {
		ctx := fmt.Sprintf("keyLen=%d", keyLen)
		h := phcFor(pw, salt, keyLen)
		noErr(t, ValidatePHCHashFormat(h), "format "+ctx)
		noErr(t, VerifyPassword(pw, h), "verify "+ctx)
		errIs(t, VerifyPassword("wrongPassword", h), ErrInvalidCredentials, "wrong password "+ctx)
	}
}

func TestValidatePHCHashFormat(t *testing.T) {
	ver := fmt.Sprintf("v=%d", argon2.Version)
	const params = "m=65536,t=3,p=4"
	okSalt, okDigest := rawB64(16), rawB64(32)

	build := func(alg, version, prm, salt, digest string) string {
		return "$" + alg + "$" + version + "$" + prm + "$" + salt + "$" + digest
	}
	std := func(prm, salt, digest string) string { return build("argon2id", ver, prm, salt, digest) }

	generated, err := HashPassword("testPassword123", cheapArgon...)
	noErr(t, err, "HashPassword")

	// largest structurally valid record: proves MaxPHCHashLen never binds
	maxRecord := std("m=4194304,t=1000,p=255", rawB64(MaxArgonSaltLen), rawB64(MaxArgonKeyLen))
	isTrue(t, len(maxRecord) <= MaxPHCHashLen, "maximum record within length cap")

	cases := []struct {
		name string
		hash string
		want error
	}{
		{"generated", generated, nil},
		{"minimal", std(params, okSalt, okDigest), nil},
		{"maximum record", maxRecord, nil},

		{"empty", "", ErrPHCInvalidFormat},
		{"plaintext", "plaintext", ErrPHCInvalidFormat},
		{"missing leading separator", "argon2id$" + ver + "$" + params + "$" + okSalt + "$" + okDigest, ErrPHCInvalidFormat},
		{"leading garbage", "x" + std(params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"leading space", " " + std(params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"too few fields", "$argon2id$" + ver + "$" + params, ErrPHCInvalidFormat},
		{"too many fields", std(params, okSalt, okDigest) + "$extra", ErrPHCInvalidFormat},
		{"over length cap", strings.Repeat("A", MaxPHCHashLen+1), ErrPHCInvalidFormat},

		{"algorithm bcrypt", build("bcrypt", ver, params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"algorithm argon2i", build("argon2i", ver, params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"algorithm argon2d", build("argon2d", ver, params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"algorithm case", build("ARGON2ID", ver, params, okSalt, okDigest), ErrPHCInvalidFormat},

		{"version empty", build("argon2id", "", params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"version malformed", build("argon2id", "version=19", params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"version leading zero", build("argon2id", "v=019", params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"version negative", build("argon2id", "v=-19", params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"version too low", build("argon2id", "v=18", params, okSalt, okDigest), ErrPHCInvalidFormat},
		{"version too high", build("argon2id", "v=20", params, okSalt, okDigest), ErrPHCInvalidFormat},

		{"parameters empty", std("", okSalt, okDigest), ErrPHCInvalidFormat},
		{"parameters reordered", std("t=3,m=65536,p=4", okSalt, okDigest), ErrPHCInvalidFormat},
		{"parameters spaced", std("m=65536, t=3, p=4", okSalt, okDigest), ErrPHCInvalidFormat},
		{"parameters trailing", std("m=65536,t=3,p=4,x=1", okSalt, okDigest), ErrPHCInvalidFormat},
		{"parameters negative", std("m=-1,t=3,p=4", okSalt, okDigest), ErrPHCInvalidFormat},
		{"parameters overflow", std("m=99999999999999999999,t=3,p=4", okSalt, okDigest), ErrPHCInvalidFormat},
		{"zero time", std("m=65536,t=0,p=4", okSalt, okDigest), ErrPHCInvalidFormat},
		{"zero memory", std("m=0,t=3,p=4", okSalt, okDigest), ErrPHCInvalidFormat},
		{"zero threads", std("m=65536,t=3,p=0", okSalt, okDigest), ErrPHCInvalidFormat},
		{"memory at cap", std("m=4194304,t=3,p=4", okSalt, okDigest), nil},
		{"memory over cap", std("m=4194305,t=3,p=4", okSalt, okDigest), ErrPHCInvalidFormat},
		{"time at cap", std("m=65536,t=1000,p=4", okSalt, okDigest), nil},
		{"time over cap", std("m=65536,t=1001,p=4", okSalt, okDigest), ErrPHCInvalidFormat},
		{"threads at cap", std("m=65536,t=3,p=255", okSalt, okDigest), nil},
		{"threads overflow", std("m=65536,t=3,p=256", okSalt, okDigest), ErrPHCInvalidFormat},

		{"salt not base64", std(params, "!!!invalid!!!", okDigest), ErrPHCInvalidSalt},
		{"salt padded", std(params, base64.StdEncoding.EncodeToString(make([]byte, 10)), okDigest), ErrPHCInvalidSalt},
		{"salt url alphabet", std(params, "abc-def_ghijklmn", okDigest), ErrPHCInvalidSalt},
		{"salt empty", std(params, "", okDigest), ErrPHCInvalidSalt},
		{"salt too short", std(params, rawB64(7), okDigest), ErrPHCInvalidSalt},
		{"salt minimum", std(params, rawB64(8), okDigest), nil},
		{"salt at cap", std(params, rawB64(MaxArgonSaltLen), okDigest), nil},
		{"salt over cap", std(params, rawB64(MaxArgonSaltLen+1), okDigest), ErrPHCInvalidSalt},

		{"digest not base64", std(params, okSalt, "!!!invalid!!!"), ErrPHCInvalidHash},
		{"digest empty", std(params, okSalt, ""), ErrPHCInvalidHash},
		{"digest too short", std(params, okSalt, rawB64(15)), ErrPHCInvalidHash},
		{"digest minimum", std(params, okSalt, rawB64(16)), nil},
		{"digest at cap", std(params, okSalt, rawB64(MaxArgonKeyLen)), nil},
		{"digest over cap", std(params, okSalt, rawB64(MaxArgonKeyLen+1)), ErrPHCInvalidHash},

		// encoding/base64 discards CR and LF, so PHC records are not
		// byte-canonical: never compare them as strings.
		{"digest with newline", std(params, okSalt, okDigest[:20]+"\n"+okDigest[20:]), nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePHCHashFormat(tc.hash)
			if tc.want == nil {
				noErr(t, err, tc.name)
				return
			}
			errIs(t, err, tc.want, tc.name)
		})
	}
}

func TestVerifyPasswordMalformedNoPanic(t *testing.T) {
	for _, h := range []string{
		"", "$", "$$$$$", "$argon2id$", strings.Repeat("$", 1000),
		"$argon2id$v=19$m=65536,t=0,p=4$" + rawB64(16) + "$" + rawB64(32),
		"$argon2id$v=19$m=65536,t=3,p=0$" + rawB64(16) + "$" + rawB64(32),
		"$argon2id$v=19$garbage$" + rawB64(16) + "$" + rawB64(32),
		"$argon2id$v=19$m=65536,t=3,p=4$$",
		"$argon2id$v=19$m=99999999999999999999,t=3,p=4$" + rawB64(16) + "$" + rawB64(32),
	} {
		hasErr(t, VerifyPassword("whatever", h), fmt.Sprintf("hash %q", h))
	}
}

func TestMigrateFromPHC(t *testing.T) {
	const user, pw = "migrationUser", "testPassword123"
	phcHash, err := HashPassword(pw, cheapArgon...)
	noErr(t, err, "HashPassword")

	cred, err := MigrateFromPHC(user, pw, phcHash)
	noErr(t, err, "MigrateFromPHC")
	eq(t, cred.Username, user, "username")
	eq(t, cred.ArgonTime, uint32(testArgonTime), "time")
	eq(t, cred.ArgonMemory, uint32(testArgonMemory), "memory")
	eq(t, cred.ArgonThreads, uint8(testArgonThreads), "threads")
	eq(t, len(cred.StoredKey), sha256.Size, "stored key length")
	eq(t, len(cred.ServerKey), sha256.Size, "server key length")

	salt, err := base64.RawStdEncoding.DecodeString(strings.Split(phcHash, "$")[4])
	noErr(t, err, "salt decode")
	eqBytes(t, cred.Salt, salt, "salt carried over")

	// migration must agree with direct derivation over the same material
	direct, err := DeriveCredential(user, pw, cred.Salt, cred.ArgonTime, cred.ArgonMemory, cred.ArgonThreads)
	noErr(t, err, "DeriveCredential")
	eqBytes(t, cred.StoredKey, direct.StoredKey, "stored key")
	eqBytes(t, cred.ServerKey, direct.ServerKey, "server key")

	// keys are derived from the salted password, not copies of it
	salted, err := base64.RawStdEncoding.DecodeString(strings.Split(phcHash, "$")[5])
	noErr(t, err, "digest decode")
	want := sha256.Sum256(computeHMAC(salted, []byte("Client Key")))
	eqBytes(t, cred.StoredKey, want[:], "stored key derivation")
	eqBytes(t, cred.ServerKey, computeHMAC(salted, []byte("Server Key")), "server key derivation")
	if bytes.Equal(cred.StoredKey, salted) || bytes.Equal(cred.ServerKey, salted) {
		t.Fatal("credential exposes the salted password")
	}

	_, err = MigrateFromPHC(user, "wrongPassword", phcHash)
	errIs(t, err, ErrInvalidCredentials, "wrong password")
	_, err = MigrateFromPHC(user, pw, "$invalid$format")
	errIs(t, err, ErrPHCInvalidFormat, "malformed record")
	_, err = MigrateFromPHC(user, strings.Repeat("a", MaxPasswordLen+1), phcHash)
	errIs(t, err, ErrPasswordTooLong, "oversized password")
}

func TestMigrateFromPHCShortSalt(t *testing.T) {
	// parsePHC accepts 8..64 byte salts; SCRAM requires >= 16. The 32-byte
	// digest branch skips that check, the fallback branch enforces it.
	// See the ‼️ note on MigrateFromPHC.
	const pw = "testPassword123"
	salt := []byte("12345678")

	cred, err := MigrateFromPHC("u", pw, phcFor(pw, salt, DefaultArgonKeyLen))
	noErr(t, err, "32-byte digest branch")
	eq(t, len(cred.Salt), 8, "short salt retained")

	// the credential it produced cannot survive an export/import cycle
	_, err = ImportCredential(cred.Export())
	errIs(t, err, ErrSCRAMSaltTooShort, "re-import")

	_, err = MigrateFromPHC("u", pw, phcFor(pw, salt, 20))
	errIs(t, err, ErrSCRAMSaltTooShort, "fallback branch")
}

func TestConcurrentPasswordOperations(t *testing.T) {
	const pw = "testPassword123"
	hash, err := HashPassword(pw, cheapArgon...)
	noErr(t, err, "HashPassword")

	const n = 16
	errs := make(chan error, 2*n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := VerifyPassword(pw, hash); err != nil {
				errs <- err
			}
			local := fmt.Sprintf("password-%04d", i)
			h, err := HashPassword(local, cheapArgon...)
			if err != nil {
				errs <- err
				return
			}
			if err := VerifyPassword(local, h); err != nil {
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

func FuzzParsePHC(f *testing.F) {
	h, err := HashPassword("testPassword123", cheapArgon...)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(h)
	f.Add("")
	f.Add("$argon2id$v=19$m=65536,t=3,p=4$" + rawB64(16) + "$" + rawB64(32))
	f.Add("$argon2id$v=19$m=0,t=0,p=0$$")

	f.Fuzz(func(t *testing.T, s string) {
		r, err := parsePHC(s)
		if err != nil {
			if r != nil {
				t.Fatalf("result returned alongside error: %v", err)
			}
			return
		}
		if r.time == 0 || r.memory == 0 || r.threads == 0 {
			t.Fatalf("zero parameter accepted: m=%d t=%d p=%d", r.memory, r.time, r.threads)
		}
		if r.memory > 4*1024*1024 || r.time > 1000 {
			t.Fatalf("cost bound exceeded: m=%d t=%d", r.memory, r.time)
		}
		if len(r.salt) < 8 || len(r.salt) > MaxArgonSaltLen {
			t.Fatalf("salt length %d accepted", len(r.salt))
		}
		if len(r.expectedHash) < 16 || len(r.expectedHash) > MaxArgonKeyLen {
			t.Fatalf("digest length %d accepted", len(r.expectedHash))
		}
	})
}

func FuzzVerifyPassword(f *testing.F) {
	h, err := HashPassword("testPassword123", cheapArgon...)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("testPassword123", h)
	f.Add("", "")
	f.Add("x", "$argon2id$v=19$m=8192,t=1,p=1$"+rawB64(16)+"$"+rawB64(32))

	f.Fuzz(func(t *testing.T, password, hash string) {
		// parsePHC admits m up to 4 GiB from untrusted input; clamp before
		// letting the fuzzer choose the KDF cost.
		if r, err := parsePHC(hash); err == nil &&
			(r.memory > 64*1024 || r.time > 4 || r.threads > 8) {
			return
		}
		_ = VerifyPassword(password, hash)
	})
}

func BenchmarkHashPasswordDefault(b *testing.B) {
	for b.Loop() {
		if _, err := HashPassword("testPassword123"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPasswordDefault(b *testing.B) {
	hash, err := HashPassword("testPassword123")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if err := VerifyPassword("testPassword123", hash); err != nil {
			b.Fatal(err)
		}
	}
}

func TestVerifyPasswordCostCeiling(t *testing.T) {
	const pw = "testPassword123"
	// well-formed per PHC, refused before the KDF runs
	over := fmt.Sprintf("$argon2id$v=%d$m=%d,t=1,p=1$%s$%s",
		argon2.Version, MaxVerifyArgonMemory+1, rawB64(16), rawB64(32))
	noErr(t, ValidatePHCHashFormat(over), "format validation is unaffected")
	errIs(t, VerifyPassword(pw, over), ErrPHCCostTooHigh, "memory over ceiling")

	overTime := fmt.Sprintf("$argon2id$v=%d$m=8192,t=%d,p=1$%s$%s",
		argon2.Version, MaxVerifyArgonTime+1, rawB64(16), rawB64(32))
	errIs(t, VerifyPassword(pw, overTime), ErrPHCCostTooHigh, "time over ceiling")
	_, err := MigrateFromPHC("u", pw, over)
	errIs(t, err, ErrPHCCostTooHigh, "migration honors the ceiling")
}
