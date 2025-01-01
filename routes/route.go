package routes

import (
	"Backend-berkah/controller"
	"Backend-berkah/helper" // Ganti helper ke middleware sesuai fungsionalitas JWT

	"github.com/gorilla/mux"
)

func RegisterAuthRoutes(router *mux.Router) {
	// Route untuk Register dan Login
	router.HandleFunc("/api/register", controller.Register).Methods("POST")
	router.HandleFunc("/api/login", controller.Login).Methods("POST")

	// Subrouter untuk data endpoints (dengan middleware JWT)
	dataRouter := router.PathPrefix("/api/data").Subrouter()
	dataRouter.Use(helper.Authenticate) // Middleware autentikasi JWT

	// CRUD endpoints
	dataRouter.HandleFunc("/", controller.GetData).Methods("GET")        // Get all data
	dataRouter.HandleFunc("/", controller.PostData).Methods("POST")     // Create data
	dataRouter.HandleFunc("/{id}", controller.UpdateData).Methods("PUT") // Update data
	dataRouter.HandleFunc("/{id}", controller.DeleteData).Methods("DELETE") // Delete data
}
