package config

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Key types untuk context values
type ContextKey int

const (
	UserIDKey ContextKey = iota
	RoleKey
)

// String representation untuk debugging
func (c ContextKey) String() string {
	switch c {
	case UserIDKey:
		return "userID"
	case RoleKey:
		return "role"
	default:
		return "unknown"
	}
}

// JwtKey will hold the JWT secret key
var JwtKey []byte

var Auth0Config = struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Audience     string
	RedirectURL  string
}{
	Domain:       os.Getenv("AUTH0_DOMAIN"),
	ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
	ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
	Audience:     "https://backend-berkah.onrender.com",
	RedirectURL:  "https://backend-berkah.onrender.com/auth/callback",
}

// Fungsi untuk menghasilkan state string yang aman
func GenerateStateString() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

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
