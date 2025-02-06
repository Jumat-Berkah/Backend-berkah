package config

import "net/http"

// Di backend routes/route.go
func SetAccessControlHeaders(w http.ResponseWriter, r *http.Request) bool {
    w.Header().Set("Access-Control-Allow-Origin", "https://jumatberkah.vercel.app")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Cache-Control")
    w.Header().Set("Access-Control-Allow-Credentials", "true")
    
    if r.Method == "OPTIONS" {
        w.WriteHeader(http.StatusOK)
        return true
    }
    return false
}