package config

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)  
  
var DB *gorm.DB  
  
// ConnectDatabase menghubungkan aplikasi ke database PostgreSQL  
func ConnectDatabase() {  
	// Ambil variabel dari .env  
	dbUser := os.Getenv("POSTGRESUSER")  
	dbPassword := os.Getenv("POSTGRESPASSWORD")  
	dbHost := os.Getenv("POSTGRESHOST")  
	dbPort := os.Getenv("POSTGRESPORT")  
	dbName := os.Getenv("POSTGRESDATABASE")  
  
	// Validasi variabel environment  
	if dbUser == "" || dbPassword == "" || dbHost == "" || dbPort == "" || dbName == "" {  
		log.Fatal("Database configuration is missing in .env file")  
	}  
  
	// Buat DSN untuk PostgreSQL  
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",  
		dbHost, dbPort, dbUser, dbPassword, dbName)  
  
	log.Printf("Connecting to database with DSN: %s", dsn)  
  
	// Koneksi ke PostgreSQL  
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})  
	if err != nil {  
		log.Fatalf("Failed to connect to database: %v", err)  
	}  
  
	// Simpan koneksi ke variabel global DB  
	DB = db  
	log.Println("Connected to the database successfully!")  
}  