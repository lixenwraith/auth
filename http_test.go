package auth

import (
	"strings"
	"testing"
)

func TestParseBearerToken(t *testing.T) {
	for _, tc := range []struct {
		header, token string
		want          error
	}{
		{"Bearer abc.def-_/+~==", "abc.def-_/+~==", nil},
		{"bEaReR  token", "token", nil},
		{"Bearer ", "", ErrAuthEmptyBearerToken},
		{"Bearer   ", "", ErrAuthEmptyBearerToken},
		{"Bearer", "", ErrAuthInvalidBearerFormat},
		{"Bearer x y", "", ErrAuthInvalidBearerFormat},
		{"Bearer x ", "", ErrAuthInvalidBearerFormat},
		{"Bearer x\r\n", "", ErrAuthInvalidBearerFormat},
		{"Bearer x\ty", "", ErrAuthInvalidBearerFormat},
		{"Bearer =", "", ErrAuthInvalidBearerFormat},
		{"Bearer a=b", "", ErrAuthInvalidBearerFormat},
		{"Other x", "", ErrAuthInvalidBearerFormat},
		{"Bearer " + strings.Repeat("x", MaxTokenLen+1), "", ErrTokenTooLong},
	} {
		token, err := ParseBearerToken(tc.header)
		if tc.want != nil {
			errIs(t, err, tc.want, tc.header)
		} else {
			noErr(t, err, tc.header)
		}
		eq(t, token, tc.token, "token")
	}
}

func FuzzParseBearerToken(f *testing.F) {
	for _, seed := range []string{"Bearer token", "bearer  abc+/==", "Bearer x\n", "Bearer a=b", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		token, err := ParseBearerToken(header)
		if err != nil {
			if token != "" {
				t.Fatal("token with error")
			}
			return
		}
		if token == "" || len(token) > MaxTokenLen || strings.ContainsAny(token, " \t\r\n") {
			t.Fatal("invalid token accepted")
		}
		again, err := ParseBearerToken("Bearer " + token)
		if err != nil || again != token {
			t.Fatal("noncanonical roundtrip")
		}
	})
}
