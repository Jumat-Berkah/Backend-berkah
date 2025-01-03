package routes

import (
	"Backend-berkah/config"
	"Backend-berkah/controller"
	"Backend-berkah/helper"
	"net/http"
	// Middleware untuk autentikasi dan otorisasi JWT
)

func URL(w http.ResponseWriter, r *http.Request) {
	if config.SetAccessControlHeaders(w, r) {
		return // If it's a preflight request, return early.
	}
	config.LoadEnv()

	var method, path string = r.Method, r.URL.Path
	switch {
	case method == "POST" && path == "/register":
		controller.Register(w, r)
	case method == "POST" && path == "/login":
		controller.Login(w, r)
	case method == "GET" && path == "/healthcheck":
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Service is running"))
	

	// dashboard berdasarkan role
	case method == "POST" && path == "/admin/dashboard":
		controller.Login(w, r)
	case method == "POST" && path == "/user/dashboard":
		controller.Login(w, r)
	default:
		helper.NotFound(w, r)
	}
}	
