package main

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
	"Backend-berkah/model"
	"Backend-berkah/routes"
	"log"
	"net/http"
	"os"
)

func main() {
	// Load environment variables
	log.Println("Loading environment variables...")
	config.LoadEnv()

	// Connect to the database
	log.Println("Connecting to the database...")
	config.ConnectDatabase()

	// Auto-migrate database schema
	log.Println("Running database migrations...")
	err := runMigrations()
	if err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}
	log.Println("Database migrations completed successfully.")

	// Start token cleanup scheduler
	log.Println("Starting token cleanup scheduler...")
	err = helper.ScheduleTokenCleanup()
	if err != nil {
		log.Fatalf("Failed to start token cleanup scheduler: %v", err)
	}
	log.Println("Token cleanup scheduler started successfully.")

	// Use PORT from the environment or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if PORT is not set
	}
	log.Printf("Server running on port %s", port)

	// Start the HTTP server
	log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(routes.URL)))
}

// runMigrations handles the migration of database models
func runMigrations() error {
	return config.DB.AutoMigrate(
		&model.Role{},          // Tabel roles
		&model.User{},          // Tabel users
		&model.ActiveToken{},   // Tabel active_tokens
		&model.BlacklistToken{}, // Tabel blacklist_tokens
		&model.Location{},      // Tabel locations
	)
}
