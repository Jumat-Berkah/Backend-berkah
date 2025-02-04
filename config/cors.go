package config

import "net/http"


  
func SetAccessControlHeaders(w http.ResponseWriter, r *http.Request) bool {  
    // Set CORS headers untuk semua request
    w.Header().Set("Access-Control-Allow-Origin", "https://jumatberkah.vercel.app") // Tambahkan https://
    w.Header().Set("Access-Control-Allow-Credentials", "true")  
    w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")  
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Login, X-Requested-With")  
  
    // Handle preflight request  
    if r.Method == http.MethodOptions {  
        w.WriteHeader(http.StatusNoContent)  
        return true  
    }  
  
    return false  
}