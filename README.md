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
phcHash, _ := auth.HashPassword("password123")
cred, _ := auth.MigrateFromPHC("user", "password123", phcHash)
server.AddCredential(cred)
```

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
go test -v ./
```