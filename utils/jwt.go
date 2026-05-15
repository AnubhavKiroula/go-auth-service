// Package utils provides JWT generation and validation utilities.
package utils

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims defines the payload embedded in every JWT issued by this service.
// Embedding jwt.RegisteredClaims gives us standard fields (ExpiresAt, IssuedAt,
// etc.) for free and ensures the library can validate expiry automatically.
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken creates and signs a JWT for the given user.
// The token is signed with HMAC-SHA256 using the JWT_SECRET from the
// environment. Expiry is fixed at 24 hours from the moment of issuance.
//
// Returns the compact serialised token string, or an error if signing fails.
func GenerateToken(userID, email, role string) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", errors.New("JWT_SECRET environment variable is not set")
	}

	claims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return signed, nil
}

// ParseToken validates the compact JWT string and returns the embedded Claims.
// It verifies:
//   - The signature against JWT_SECRET (prevents tampering)
//   - The token has not expired (handled automatically by the library)
//   - The signing method is HMAC (guards against the "alg: none" attack)
//
// Returns a non-nil error for any of: malformed token, bad signature,
// expired token, or wrong algorithm.
func ParseToken(tokenString string) (*Claims, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_SECRET environment variable is not set")
	}

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		// Explicitly reject any algorithm that isn't HMAC to prevent
		// the "alg: none" / algorithm confusion attack.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
