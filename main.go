package main

import (
	"Backend-berkah/config"
	"Backend-berkah/routes"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	// Load environment variables
	config.LoadEnv()

	// Connect to the database
	config.ConnectDatabase()

	// Create a new router
	router := mux.NewRouter()

	// Add a healthcheck route
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Service is running"))
	})

	// Register routes
	routes.RegisterAuthRoutes(router)
	
	// Use PORT from the environment or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if PORT is not set
	}

	// Start the server
	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
