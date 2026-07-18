# Auth Package

Modular authentication utilities for Go applications.

## Features

- **Password Hashing**: Standalone Argon2id hashing with PHC format.
- **JWT**: HS256/RS256 token management via a simple facade over `golang-jwt`.
- **SCRAM-SHA256**: Client/server implementation with Argon2id KDF.
- **HTTP Auth**: Helpers for parsing Basic and Bearer authentication headers.

## Usage

```go
// Argon2 Password Hashing
hash, _ := auth.HashPassword("password123")
err := auth.VerifyPassword("password123", hash)

// JWT with HS256
jwtMgr, _ := auth.NewJWT([]byte("a-very-secure-32-byte-secret-key"))
token, _ := jwtMgr.GenerateToken("user123", map[string]any{"role": "admin"})
userID, claims, _ := jwtMgr.ValidateToken(token)

// SCRAM authentication
server := auth.NewScramServer()
defer server.Stop()
phcHash, _ := auth.HashPassword("password123")
cred, _ := auth.MigrateFromPHC("user", "password123", phcHash)
server.AddCredential(cred)
```

### SCRAM contract notes

- Unknown usernames succeed at `ProcessClientFirstMessage` and fail at
  `ProcessClientFinalMessage` with `ErrInvalidCredentials`. This is deliberate
  user-enumeration protection. Do not log the first message as an auth success.
- Decoy Argon2 parameters mirror the most recently added credential. Provision
  all credentials in a deployment with identical parameters, or the decoy shape
  becomes a distinguisher.
- Passwords are bounded by `MaxPasswordLen` (1024 bytes) at every KDF entry
  point.

## Package Structure

- `doc.go` - Overview and package documentation
- `argon2.go` - Standalone Argon2id password hashing
- `jwt.go` - JWT manager (HS256/RS256) wrapping `golang-jwt`
- `scram.go` - SCRAM-SHA256 client/server protocol
- `http.go` - HTTP Basic/Bearer header parsing
- `token.go` - Simple in-memory token validator
- `error.go` - Centralized error definitions

## Testing

```bash
go test ./... -race -count=1
go test ./... -run '^$' -bench . -benchmem

# fuzz targets (run individually)
go test -run '^$' -fuzz FuzzParsePHC -fuzztime 60s
go test -run '^$' -fuzz FuzzVerifyPassword -fuzztime 60s
go test -run '^$' -fuzz FuzzImportCredential -fuzztime 60s
go test -run '^$' -fuzz FuzzValidateHS256Token -fuzztime 60s
go test -run '^$' -fuzz FuzzParseBasicAuth -fuzztime 30s
```

