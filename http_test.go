package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func basicHeader(payload string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(payload))
}

func TestParseBasicAuth(t *testing.T) {
	cases := []struct {
		name, header, username, password string
		want                             error
	}{
		{name: "standard", header: basicHeader("user:pass"), username: "user", password: "pass"},
		{name: "empty password", header: basicHeader("user:"), username: "user"},
		{name: "empty username", header: basicHeader(":pass"), password: "pass"},
		{name: "colon in password", header: basicHeader("user:pa:ss"), username: "user", password: "pa:ss"},
		{name: "unicode", header: basicHeader("üser:pässwörd"), username: "üser", password: "pässwörd"},
		{name: "separator only", header: basicHeader(":")},

		{name: "missing scheme", header: "Invalid header", want: ErrAuthInvalidBasicFormat},
		{name: "no space", header: "Basic", want: ErrAuthInvalidBasicFormat},
		{name: "empty header", header: "", want: ErrAuthInvalidBasicFormat},
		// ☢ RFC 7235 auth-scheme is case-insensitive; matching here is not
		{name: "lowercase scheme", header: "basic dXNlcjpwYXNz", want: ErrAuthInvalidBasicFormat},
		{name: "bad base64", header: "Basic not-base64!", want: ErrAuthInvalidBasicEncoding},
		{name: "no colon", header: basicHeader("no-colon"), want: ErrAuthInvalidBasicCreds},
		{name: "empty payload", header: "Basic ", want: ErrAuthInvalidBasicCreds},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			username, password, err := ParseBasicAuth(tc.header)
			if tc.want != nil {
				errIs(t, err, tc.want, tc.name)
				eq(t, username, "", "username on failure")
				eq(t, password, "", "password on failure")
				return
			}
			noErr(t, err, tc.name)
			eq(t, username, tc.username, "username")
			eq(t, password, tc.password, "password")
		})
	}
}

func TestParseBearerToken(t *testing.T) {
	cases := []struct {
		name, header, token string
		want                error
	}{
		{name: "standard", header: "Bearer test-token-xyz", token: "test-token-xyz"},
		{name: "embedded space", header: "Bearer a b", token: "a b"},
		{name: "trailing space", header: "Bearer x ", token: "x "},

		{name: "empty token", header: "Bearer ", want: ErrAuthEmptyBearerToken},
		{name: "missing scheme", header: "Invalid header", want: ErrAuthInvalidBearerFormat},
		{name: "lowercase scheme", header: "bearer x", want: ErrAuthInvalidBearerFormat},
		{name: "no space", header: "Bearer", want: ErrAuthInvalidBearerFormat},
		{name: "empty header", header: "", want: ErrAuthInvalidBearerFormat},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := ParseBearerToken(tc.header)
			if tc.want != nil {
				errIs(t, err, tc.want, tc.name)
				eq(t, token, "", "token on failure")
				return
			}
			noErr(t, err, tc.name)
			eq(t, token, tc.token, "token")
		})
	}
}

func TestExtractAuthType(t *testing.T) {
	cases := map[string]string{
		"Basic dXNlcjpwYXNz": "Basic",
		"Bearer token":       "Bearer",
		"Custom somedata":    "Custom",
		"Basic ":             "Basic",
		"InvalidHeader":      "",
		"":                   "",
		" Bearer token":      "", // cut at the first space yields an empty scheme
	}
	for header, want := range cases {
		eq(t, ExtractAuthType(header), want, fmt.Sprintf("header %q", header))
	}
}

func FuzzParseBasicAuth(f *testing.F) {
	f.Add(basicHeader("user:pass"))
	f.Add("Basic ")
	f.Add("")
	f.Add("Basic !!!")

	f.Fuzz(func(t *testing.T, header string) {
		username, password, err := ParseBasicAuth(header)
		if err != nil {
			if username != "" || password != "" {
				t.Fatal("values returned alongside error")
			}
			return
		}
		encoded, ok := strings.CutPrefix(header, "Basic ")
		if !ok {
			t.Fatal("accepted a header without the Basic prefix")
		}
		decoded, decErr := base64.StdEncoding.DecodeString(encoded)
		if decErr != nil {
			t.Fatal("accepted an undecodable payload")
		}
		if string(decoded) != username+":"+password {
			t.Fatalf("lossy split: %q vs %q", decoded, username+":"+password)
		}
	})
}
