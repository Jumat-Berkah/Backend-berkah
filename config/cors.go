package config

import "net/http"

func SetAccessControlHeaders(w http.ResponseWriter, r *http.Request) bool {  
    // Izinkan multiple origins
    allowedOrigins := []string{
        "https://jumatberkah.vercel.app",
        "https://backend-berkah.onrender.com",
    }
    
    // Cek origin dari request
    origin := r.Header.Get("Origin")
    for _, allowedOrigin := range allowedOrigins {
        if origin == allowedOrigin {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            break
        }
    }
    
    // Set header CORS lainnya
    w.Header().Set("Access-Control-Allow-Credentials", "true")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
    
    // Handle preflight request
    if r.Method == "OPTIONS" {
        w.WriteHeader(http.StatusNoContent)
        return true
    }
    
    return false
}

// Fungsi helper untuk mengecek apakah origin diizinkan
func IsAllowedOrigin(origin string) bool {
    allowedOrigins := []string{
        "https://jumatberkah.vercel.app",
        "https://dev-a5578emn1asaeic0.us.auth0.com",
        "https://backend-berkah.onrender.com",
    }
    
    for _, allowed := range allowedOrigins {
        if origin == allowed {
            return true
        }
    }
    return false
}