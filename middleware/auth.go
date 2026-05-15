// Package middleware provides HTTP middleware for the go-auth-service.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/AnubhavKiroula/go-auth-service/utils"
)

// ── Context key types ─────────────────────────────────────────────────────────
//
// Using a private, unexported type as the context key prevents any external
// package from accidentally (or maliciously) reading or overwriting the claims
// stored in the context. Two packages using the plain string "claims" as a key
// would silently collide; two packages using their own distinct types cannot.

type contextKey string

const claimsKey contextKey = "claims"

// ── Middleware ────────────────────────────────────────────────────────────────

// Authenticate is a chi-compatible middleware that validates a Bearer JWT.
//
// Step-by-step:
//  1. Read the Authorization header.
//  2. Check it starts with "Bearer " — if not, return 401.
//  3. Strip the prefix to get the raw token string.
//  4. Call utils.ParseToken to validate the signature and check expiry.
//  5. If invalid or expired, return 401.
//  6. Store the verified *Claims in the request context under claimsKey.
//  7. Call next.ServeHTTP to continue down the handler chain.
//
// Handlers downstream retrieve claims with GetClaimsFromContext().
func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}

		// Enforce the "Bearer <token>" format exactly
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "Authorization header must start with 'Bearer '")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			writeError(w, http.StatusUnauthorized, "token is empty")
			return
		}

		claims, err := utils.ParseToken(tokenString)
		if err != nil {
			// Do not expose internal JWT error details to the caller.
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Inject verified claims into the request context so handlers can
		// access user_id, email, and role without re-parsing the token.
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole returns a middleware that allows only users whose role matches
// one of the allowed roles. It must be used after Authenticate — it assumes
// claims are already in the context.
//
// Usage inside a chi router:
//
//	r.With(middleware.Authenticate, middleware.RequireRole("admin")).Get("/users", handlers.ListUsers)
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	// Build a set for O(1) lookup
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaimsFromContext(r.Context())
			if !ok {
				// This should never happen when RequireRole is used after
				// Authenticate, but guard anyway.
				writeError(w, http.StatusUnauthorized, "no auth claims in context")
				return
			}

			if _, permitted := allowed[claims.Role]; !permitted {
				writeError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ── Context helpers ───────────────────────────────────────────────────────────

// GetClaimsFromContext retrieves the JWT claims stored by Authenticate.
// Returns (claims, true) when present; (nil, false) otherwise.
//
// Handlers call this to read user_id, email, or role without coupling to the
// middleware's internal context key.
func GetClaimsFromContext(ctx context.Context) (*utils.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*utils.Claims)
	return claims, ok && claims != nil
}

// ── Private helper ────────────────────────────────────────────────────────────

// writeError writes a standard {"error":"..."} JSON response.
// Duplicated here (instead of importing from handlers) to keep the middleware
// package self-contained with zero circular imports.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck
	w.Write([]byte(`{"error":"` + msg + `"}`))
}
