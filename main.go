package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AnubhavKiroula/go-auth-service/config"
	"github.com/AnubhavKiroula/go-auth-service/handlers"
	authMW "github.com/AnubhavKiroula/go-auth-service/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Connect to PostgreSQL and run schema migration
	config.InitDB()
	defer config.DB.Close()

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

	// Public authentication routes
	r.Post("/signup", handlers.Signup)
	r.Post("/login", handlers.Login)

	// Protected routes — require a valid JWT
	r.Group(func(r chi.Router) {
		r.Use(authMW.Authenticate)

		// GET /profile — any authenticated role
		r.Get("/profile", handlers.GetProfile)

		// GET /users — admin only
		r.With(authMW.RequireRole("admin")).Get("/users", handlers.ListUsers)
	})

	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
