# Auth Package

Pluggable authentication utilities for Go applications.

## Features

- **Password Hashing**: Argon2id with PHC format
- **JWT**: HS256/RS256 token generation and validation
- **SCRAM-SHA256**: Client/server implementation with Argon2id KDF
- **HTTP Auth**: Basic/Bearer header parsing

## Usage
```go
// JWT with HS256
auth, _ := auth.NewAuthenticator([]byte("32-byte-secret-key..."))
token, _ := auth.GenerateToken("user123", map[string]interface{}{"role": "admin"})
userID, claims, _ := auth.ValidateToken(token)

// SCRAM authentication
server := auth.NewScramServer()
cred, _ := auth.DeriveCredential("user", "password", salt, 1, 65536, 4)
server.AddCredential(cred)
```

## Package Structure

- `interfaces.go` - Core interfaces
- `jwt.go` - JWT token operations
- `argon2.go` - Password hashing
- `scram.go` - SCRAM-SHA256 protocol
- `token.go` - Token validation utilities
- `http.go` - HTTP header parsing
- `errors.go` - Error definitions

## Testing
```bash
go test -v ./auth
```