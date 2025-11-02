// FILE: auth/interface.go
package auth

// AuthenticatorInterface defines the authentication operations
type AuthenticatorInterface interface {
	HashPassword(password string) (hash string, err error)
	VerifyPassword(password, hash string) (err error)
	GenerateToken(userID string, claims map[string]any) (token string, err error)
	ValidateToken(token string) (userID string, claims map[string]any, err error)
}

// TokenValidator validates bearer tokens
type TokenValidator interface {
	ValidateToken(token string) (valid bool)
	AddToken(token string)
	RemoveToken(token string)
}