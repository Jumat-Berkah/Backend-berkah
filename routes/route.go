package routes

import (
	"Backend-berkah/config"
	"Backend-berkah/controller"
	"Backend-berkah/helper"
	"log"
	"net/http"
	// Middleware untuk autentikasi dan otorisasi JWT
)

func URL(w http.ResponseWriter, r *http.Request) {
	// Log request method dan path
	log.Printf("Incoming request: %s %s", r.Method, r.URL.Path)

	// Set Access Control Headers
	if config.SetAccessControlHeaders(w, r) {
		return
	}

	// Load environment variables
	config.LoadEnv()

	// Ambil metode dan path dari request
	method := r.Method
	path := r.URL.Path

	// Routing berdasarkan method dan path
	switch {
	// User authentication routes
	case method == "POST" && path == "/register":
		controller.Register(w, r)
	case method == "POST" && path == "/login":
		controller.Login(w, r)
	case method == "POST" && path == "/logout":
		controller.Logout(w, r)
	case method == "GET" && path == "/healthcheck":
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Service is running"))

	// CRUD routes (with JWT Middleware)
	case method == "GET" && path == "/datalokasi":
		helper.ValidateTokenMiddleware(http.HandlerFunc(controller.GetDataLocation)).ServeHTTP(w, r)
	case method == "POST" && path == "/create/data":
		helper.ValidateTokenMiddleware(helper.RoleMiddleware("admin")(http.HandlerFunc(controller.CreateDataLocation))).ServeHTTP(w, r)

	// Logout route
	case method == "POST" && path == "/logout":
		helper.ValidateTokenMiddleware(http.HandlerFunc(helper.BlacklistToken)).ServeHTTP(w, r)

	// Default route
	default:
		helper.NotFound(w, r)
	}
}	
