package config

import (
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)  
  
var DB *gorm.DB  
  
// ConnectDatabase connects the application to the PostgreSQL database  
func ConnectDatabase() {  
	// Get the DATABASE_URL from .env  
	dbURL := os.Getenv("DATABASE_URL")  
  
	// Validate the DATABASE_URL environment variable  
	if dbURL == "" {  
		log.Fatal("DATABASE_URL is missing in .env file")  
	}  
  
	log.Printf("Connecting to database with DATABASE_URL: %s", dbURL)  
  
	// Set GORM logger to log SQL statements  
	gormLogger := logger.New(  
		log.New(os.Stdout, "\r\n", log.LstdFlags), // Output to stdout  
		logger.Config{  
			SlowThreshold:             200 * time.Millisecond, // Log slow SQL queries  
			LogLevel:                 logger.Info,             // Log level  
			IgnoreRecordNotFoundError: true,                   // Ignore ErrRecordNotFound  
			Colorful:                 true,                    // Enable colorful logging  
		},  
	)  
  
	// Connect to PostgreSQL using the DATABASE_URL  
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{  
		Logger: gormLogger,  
	})  
	if err != nil {  
		log.Fatalf("Failed to connect to database: %v", err)  
	}  
  
	// Save the connection to the global DB variable  
	DB = db  
	log.Println("Connected to the database successfully!")  
}  
