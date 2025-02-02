package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var UserIDKey = "userID"  

var RoleKey = "role" 

// JwtKey will hold the JWT secret key
var JwtKey []byte

var (
    GoogleOauthConfig = oauth2.Config{
        RedirectURL:  "https://rrq-dev.github.io/jumatberkah.github.io/auth/callback",
        ClientID:     os.Getenv("CLIENT_ID"),
        ClientSecret: os.Getenv("CLIENT_SECRET"),
        Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
        Endpoint:     google.Endpoint,
    }
    OauthStateString = "random-state"
)

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
