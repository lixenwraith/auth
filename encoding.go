package auth

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Bound allocation before decoding and reject non-canonical encodings, including
// CR/LF (which encoding/base64 accepts even in Strict mode).
func decodeBase64(s string, encoding *base64.Encoding, maxBytes int) ([]byte, error) {
	if len(s) > encoding.EncodedLen(maxBytes) || strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("invalid base64 length or whitespace")
	}
	b, err := encoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) > maxBytes {
		return nil, errors.New("decoded value exceeds limit")
	}
	return b, nil
}
