package config

import "net/http"

// SetAccessControlHeaders handles CORS for preflight and main requests
func SetAccessControlHeaders(w http.ResponseWriter, r *http.Request) bool {
	// Set CORS headers for all requests
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:5500") // Ganti dengan "*" untuk mengizinkan semua origin (hanya untuk pengembangan)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Login, X-Requested-With")

	// Handle preflight request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}

	// Handle main request
	return false
}
