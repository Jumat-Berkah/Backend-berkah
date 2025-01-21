package config

import "net/http"

// SetAccessControlHeaders handles CORS for preflight and main requests
func SetAccessControlHeaders(w http.ResponseWriter, r *http.Request) bool {
	// Set CORS headers for all requests
	w.Header().Set("Access-Control-Allow-Origin", "https://rrq-dev.github.io/jumatberkah.github.io/") 
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
