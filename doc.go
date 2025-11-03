// FILE: auth/doc.go
package auth

/*
Package auth provides modular authentication components:

# Argon2 Password Hashing

Standalone password hashing using Argon2id:

	hash, err := auth.HashPassword("password123")
	err = auth.VerifyPassword("password123", hash)

	// With custom parameters
	hash, err := auth.HashPassword("password123",
		auth.WithTime(5),
		auth.WithMemory(128*1024))

# JWT Token Management

JSON Web Token generation and validation:

	// HS256 (symmetric)
	jwtMgr, _ := auth.NewJWT(secret)
	token, _ := jwtMgr.GenerateToken("user1", claims)
	userID, claims, _ := jwtMgr.ValidateToken(token)

	// RS256 (asymmetric)
	jwtMgr, _ := auth.NewJWTRSA(privateKey)

	// One-off operations
	token, _ := auth.GenerateHS256Token(secret, "user1", claims, 1*time.Hour)

# SCRAM-SHA256 Authentication

Server and client implementation for SCRAM:

	// Server
	server := auth.NewScramServer()
	server.AddCredential(credential)

	// Client
	client := auth.NewScramClient(username, password)

# HTTP Authentication Parsing

Utility functions for HTTP headers:

	username, password, _ := auth.ParseBasicAuth(header)
	token, _ := auth.ParseBearerToken(header)

Each module can be used independently without initializing other components.
*/