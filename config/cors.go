package config

import "net/http"

var Origins = []string{
    "https://jumatberkah.vercel.app",
	
}

var Headers = []string{
	"Origin",
	"Content-Type",
	"Accept",
	"Authorization",
	"Access-Control-Request-Headers",
	"Token",
	"Login",
	"Access-Control-Allow-Origin",
	"Bearer",
	"X-Requested-With",
} 


func SetAccessControlHeaders(w http.ResponseWriter, r *http.Request) bool {  
    // Set CORS headers
    w.Header().Set("Access-Control-Allow-Origin", "https://jumatberkah.vercel.app")
    w.Header().Set("Access-Control-Allow-Credentials", "true")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
    w.Header().Set("Access-Control-Max-Age", "3600")
    
    // Handle preflight
    if r.Method == http.MethodOptions {
        w.WriteHeader(http.StatusNoContent)
        return true
    }
    
    return false
}