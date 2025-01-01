package routes

import (
	"Backend-berkah/controller"
	"Backend-berkah/helper"

	"github.com/gorilla/mux"
)

func RegisterAuthRoutes(router *mux.Router) {
	// Route untuk register
	router.HandleFunc("/api/register", controller.Register).Methods("POST")
	// Route untuk login
	router.HandleFunc("/api/login", controller.Login).Methods("POST")

	dataRouter := router.PathPrefix("/api/data").Subrouter()
	dataRouter.Use(helper.Authenticate)

	// CRUD endpoints
	dataRouter.HandleFunc("/", controller.GetData).Methods("GET")        // Get all data
	dataRouter.HandleFunc("/", controller.PostData).Methods("POST")     // Create data
	dataRouter.HandleFunc("/{id}", controller.UpdateData).Methods("PUT") // Update data
	dataRouter.HandleFunc("/{id}", controller.DeleteData).Methods("DELETE") // Delete data
}