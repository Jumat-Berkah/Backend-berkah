package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// JwtKey will hold the JWT secret key
var JwtKey []byte

// LoadEnv loads environment variables and initializes JwtKey
func LoadEnv() {
	// Attempt to load the .env file
	log.Println("Loading environment variables...")
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found. Using system environment variables...")
	}

	// Load JWT secret key from environment variables
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatalf("Error: JWT_SECRET is not set. Please set it in the .env file or as an environment variable.")
	}

	JwtKey = []byte(jwtSecret)
	log.Println("Environment variables loaded successfully!")
}
