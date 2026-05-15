package models

import "time"

// User represents a row in the users table.
// The json tags control serialization — PasswordHash is always omitted
// from API responses so it is never accidentally leaked.
type User struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // never serialised to JSON
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}
