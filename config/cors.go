package config

import "net/http"


func SetAccessControlHeaders(w http.ResponseWriter, r *http.Request) bool {
	// Set CORS headers for the preflight request
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Login")
		w.Header().Set("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE")
		w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:8080")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	// Set CORS headers for the main request.
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Origin", "127.0.0.1:8080")
	w.Header().Set("Access-Control-Allow-Methods", "POST,GET,PUT,DELETE")
	return false
}