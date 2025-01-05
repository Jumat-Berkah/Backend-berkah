package main

import (
	"Backend-berkah/config"
	"Backend-berkah/routes"
	"log"
	"net/http"
	"os"
)

func main() {
	// Load environment variables
	config.LoadEnv()

	// Connect to the database
	config.ConnectDatabase()

	// auto migrate
	config.DB.AutoMigrate()

	// Use PORT from the environment or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if PORT is not set
	}

	// Start the server
	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(routes.URL)))
}
