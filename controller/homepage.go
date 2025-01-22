package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
	"Backend-berkah/model"
	"encoding/json"
	"log"
	"net/http"
)

// GetLocationByID retrieves a location by its ID
func GetLocationByID(w http.ResponseWriter, r *http.Request) {  
    // Set CORS headers  
    if config.SetAccessControlHeaders(w, r) {  
        return // Jika ini adalah permintaan preflight, keluar dari fungsi  
    }  
  
    // Set content type to JSON  
    w.Header().Set("Content-Type", "application/json")  
  
    // Validate the token from the Authorization header  
    tokenString, err := helper.GetTokenFromHeader(r)  
    if err != nil {  
        log.Printf("Token error: %v", err)  
        http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)  
        return  
    }  
  
    // Check if the token is blacklisted  
    if helper.IsTokenBlacklisted(tokenString) {  
        log.Printf("Token is blacklisted: %v", tokenString)  
        http.Error(w, "Unauthorized: Token has been blacklisted", http.StatusUnauthorized)  
        return  
    }  
  
    // Verify the JWT token  
    claims := &model.Claims{}  
    if err := helper.ParseAndValidateToken(tokenString, claims); err != nil {  
        log.Printf("Token validation error: %v", err)  
        http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)  
        return  
    }  
  
    // Ambil ID dari query parameter  
    idStr := r.URL.Query().Get("id")  
    if idStr == "" {  
        http.Error(w, "ID is required", http.StatusBadRequest)  
        return  
    }  
  
    var location model.Location  
    if err := config.DB.First(&location, idStr).Error; err != nil {  
        log.Printf("Failed to retrieve location: %v", err)  
        http.Error(w, "Location not found.", http.StatusNotFound)  
        return  
    }  
  
    // Kembalikan data lokasi  
    w.WriteHeader(http.StatusOK)  
    json.NewEncoder(w).Encode(location)  
}  
