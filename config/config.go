package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

var JwtKey []byte

// LoadEnv untuk membaca file .env
func LoadEnv() {
	// Load file .env
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Ambil secret key dari .env
	JwtKey = []byte(os.Getenv("JWT_SECRET"))
	if len(JwtKey) == 0 {
		log.Fatalf("JWT_SECRET not set in .env file")
	}
}