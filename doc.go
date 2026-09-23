// Package auth provides independent Argon2id password hashing, Argon2-SCRAM
// challenge/response authentication, HS256/RS256 JWTs, and opaque token utilities.
//
// NewCredential provisions a SCRAM credential in one KDF pass. ScramServer holds
// validated credential copies and bounded, single-use handshakes. ScramClient
// performs one exchange at a time and must verify the server's final signature
// before the application trusts the authentication result.
//
// The SCRAM exchange uses a package-specific Argon2id/JSON protocol; it is not
// interoperable with the standard SASL SCRAM-SHA-256 mechanism. Applications must
// supply authenticated TLS, request limits, rate limits, and authorization.
//
// NewJWT and NewJWTRSA create reusable, concurrent token managers. Configure an
// issuer and audience for each service. ValidateToken requires expiration and a
// nonempty subject; it returns only the nested "extra" application claims. The
// one-off HS256 helpers retain their existing API for consumers such as chess.
//
// See the README and doc/security-audit.md for limits, migration, transport
// requirements, persistence, and deployment guidance.
package auth
