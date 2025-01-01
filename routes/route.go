package routes

import (
	"Backend-berkah/controller"

	"github.com/gorilla/mux"
)

func RegisterAuthRoutes(router *mux.Router) {
	// Route untuk register
	router.HandleFunc("/api/register", controller.Register).Methods("POST")

	// Route untuk login
	router.HandleFunc("/api/login", controller.Login).Methods("POST")
}