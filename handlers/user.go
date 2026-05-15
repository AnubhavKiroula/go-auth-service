// handlers/user.go — protected user endpoints
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AnubhavKiroula/go-auth-service/config"
	"github.com/AnubhavKiroula/go-auth-service/middleware"
	"github.com/AnubhavKiroula/go-auth-service/models"
)

// GetProfile handles GET /profile.
//
// Protected: requires a valid JWT (enforced by middleware.Authenticate).
// Any role may access this endpoint.
//
// Flow:
//  1. Retrieve JWT claims from context (set by Authenticate middleware).
//  2. Query the users table for the authenticated user's own row by user_id.
//  3. Return the user object — PasswordHash is omitted via json:"-" on the struct.
func GetProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "no auth claims in context")
		return
	}

	query := `
		SELECT id, name, email, role, created_at
		FROM users
		WHERE id = $1
	`

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var user models.User
	err := config.DB.QueryRow(ctx, query, claims.UserID).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Role,
		&user.CreatedAt,
	)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// ListUsers handles GET /users.
//
// Protected: requires a valid JWT AND role == "admin"
// (role guard is applied in the router, not here, keeping the handler pure).
//
// Returns all users from the database ordered by created_at ascending.
// PasswordHash is never included — the models.User struct has json:"-" on it.
func ListUsers(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT id, name, email, role, created_at
		FROM users
		ORDER BY created_at ASC
	`

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := config.DB.Query(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch users")
		return
	}
	defer rows.Close()

	users := make([]models.User, 0) // initialise to empty slice so JSON encodes [] not null
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan user row")
			return
		}
		users = append(users, u)
	}

	// rows.Err() catches any error that occurred during iteration
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error reading users")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(users),
		"users": users,
	})
}

// ── Package-level helpers (shared by auth.go and user.go) ────────────────────

// writeJSON serialises v as JSON and writes it with the given HTTP status.
// The Content-Type header is always set to application/json.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// writeError writes a standard {"error":"..."} JSON body.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
