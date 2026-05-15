package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Initialize the chi router
	r := chi.NewRouter()

	// Global middleware stack
	r.Use(middleware.Logger)    // Logs every request with method, path, status, and latency
	r.Use(middleware.Recoverer) // Recovers from panics gracefully, returns 500
	r.Use(middleware.RequestID) // Attaches a unique X-Request-Id to every request

	// Health check — publicly accessible
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok","message":"go-auth-service is running"}`)
	})

	// TODO (feature/auth): Register POST /signup and POST /login
	// TODO (feature/protected-routes): Register GET /profile and GET /users under JWT middleware

	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
