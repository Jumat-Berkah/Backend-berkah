package main

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"Backend-berkah/routes"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	// Muat environment variables
	config.LoadEnv()

	// Koneksi ke database
	config.ConnectDatabase()

	// Migrasi tabel
	err := config.DB.AutoMigrate(
		&model.User{}, // Tambahkan tabel lainnya di sini jika ada tabel lain
	)
	if err != nil {
		log.Fatalf("Gagal migrasi database: %v", err)
	}
	log.Println("Migrasi database berhasil!")

	// Buat router baru
	router := mux.NewRouter()

	// Daftarkan auth routes
	routes.RegisterAuthRoutes(router)

	// Jalankan server
	log.Println("Server berjalan di http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
