// Package handlers contains the HTTP handler functions for authentication routes.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/AnubhavKiroula/go-auth-service/config"
	"github.com/AnubhavKiroula/go-auth-service/models"
	"github.com/AnubhavKiroula/go-auth-service/utils"
	"golang.org/x/crypto/bcrypt"
)

// ── Request / Response types ──────────────────────────────────────────────────

// signupRequest is the expected JSON body for POST /signup.
type signupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // "user" | "admin"
}

// loginRequest is the expected JSON body for POST /login.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// writeJSON serialises v as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// writeError writes a standard {"error":"..."} JSON body.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// Signup handles POST /signup.
//
// Flow:
//  1. Decode JSON body into signupRequest.
//  2. Validate required fields.
//  3. Normalise the role to "user" if not explicitly "admin".
//  4. Hash the plaintext password with bcrypt (cost 12).
//  5. Insert a new row into the users table.
//  6. Return 201 Created with a success message.
//
// Duplicate email is caught by the UNIQUE constraint and returns 409 Conflict.
func Signup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Password = strings.TrimSpace(req.Password)

	if req.Name == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "name, email, and password are required")
		return
	}
	if len(req.Password) < 6 {
		writeError(w, http.StatusBadRequest, "password must be at least 6 characters")
		return
	}

	// Default role to "user" unless explicitly "admin"
	if req.Role != "admin" {
		req.Role = "user"
	}

	// Hash the password — bcrypt cost 12 is the recommended production default
	// (slow enough to deter brute force, fast enough not to bottleneck the API).
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Insert user; the DB generates the UUID and created_at automatically.
	query := `
		INSERT INTO users (name, email, password_hash, role)
		VALUES ($1, $2, $3, $4)
	`
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err = config.DB.Exec(ctx, query, req.Name, req.Email, string(hash), req.Role)
	if err != nil {
		// pgx error code 23505 = unique_violation (duplicate email)
		if strings.Contains(err.Error(), "23505") {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"message": "user created successfully",
	})
}

// Login handles POST /login.
//
// Flow:
//  1. Decode JSON body into loginRequest.
//  2. Look up the user by email.
//  3. Compare the supplied password against the stored bcrypt hash.
//  4. Generate a signed JWT containing user_id, email, role.
//  5. Return 200 OK with the token.
//
// To avoid leaking whether an email exists, both "user not found" and
// "wrong password" return the same 401 with a generic message.
func Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Password = strings.TrimSpace(req.Password)

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	// Fetch the user record
	query := `
		SELECT id, name, email, password_hash, role, created_at
		FROM users
		WHERE email = $1
	`
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var user models.User
	err := config.DB.QueryRow(ctx, query, req.Email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
	)
	if err != nil {
		// Return a generic error — do not reveal whether the email exists.
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Compare the plaintext password against the stored hash.
	// bcrypt.CompareHashAndPassword is constant-time and safe against
	// timing attacks.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Generate a signed JWT for the authenticated user
	token, err := utils.GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"token":   token,
		"message": "login successful",
	})
}
