package config

import (
	"Backend-berkah/model"
	"fmt"
	"log"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

// ConnectDatabase menghubungkan aplikasi ke database MySQL
func ConnectDatabase() {
	// Ambil variabel dari .env
	dbUser := os.Getenv("MYSQLUSER")
	dbPassword := os.Getenv("MYSQLPASSWORD")
	dbHost := os.Getenv("MYSQLHOST")
	dbPort := os.Getenv("MYSQLPORT")
	dbName := os.Getenv("MYSQLDATABASE")

	// Validasi variabel environment
	if dbUser == "" || dbPassword == "" || dbHost == "" || dbPort == "" || dbName == "" {
		log.Fatal("Database configuration is missing in .env file")
	}

	// Buat DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	// Koneksi ke MySQL
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Simpan koneksi ke variabel global DB
	DB = db
	log.Println("Connected to the database successfully!")
}

// AutoMigrateModels melakukan migrasi otomatis untuk semua model
func AutoMigrateModels() {
	if DB == nil {
		log.Fatal("Database connection is not initialized")
	}

	// Jalankan auto-migrasi untuk model
	err := DB.AutoMigrate(
		&model.User{},          // Model untuk tabel users
		&model.ActiveToken{},   // Model untuk tabel active_tokens
		&model.Location{},      // Model untuk tabel locations
		&model.BlacklistToken{}, // Model untuk tabel blacklist_tokens
		&model.Role{},
	)
	if err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	log.Println("Database models migrated successfully!")
}
