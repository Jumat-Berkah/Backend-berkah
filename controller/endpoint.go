package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
	"Backend-berkah/model"
	"encoding/json"
	"log"
	"net/http"
)

// GetAllLocation handles the retrieval of all locations
func GetAllLocation(w http.ResponseWriter, r *http.Request) {    
	// Set CORS headers    
	if config.SetAccessControlHeaders(w, r) {    
		return // If it's a preflight request, return early    
	}    
    
	// Check for JWT token in the Authorization header    
	authHeader := r.Header.Get("Authorization")    
	if authHeader == "" {    
		http.Error(w, "Authorization header is missing", http.StatusUnauthorized)    
		return    
	}    
  
	// Extract the token from the Authorization header  
	tokenString := authHeader[len("Bearer "):] // Assuming the format is "Bearer <token>"  
  
	// Validate the token  
	claims := &model.Claims{}  
	if err := helper.ParseAndValidateToken(tokenString, claims); err != nil {  
		http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)  
		return  
	}  
  
	// Retrieve up to 20 locations from the database  
	var locations []model.Location  
	if err := config.DB.Limit(15).Find(&locations).Error; err != nil {  
		http.Error(w, "Could not retrieve locations: "+err.Error(), http.StatusInternalServerError)  
		return  
	}  
  
	// Return the locations as JSON  
	w.Header().Set("Content-Type", "application/json")  
	json.NewEncoder(w).Encode(locations)  
}  
  
// CreateLocation handles POST requests to create new location data  
func CreateLocation(w http.ResponseWriter, r *http.Request) {  
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
  
	// Parse the request body to extract location details  
	var location model.Location  
	if err := json.NewDecoder(r.Body).Decode(&location); err != nil {  
		log.Printf("Failed to decode request body: %v", err)  
		http.Error(w, "Invalid request body", http.StatusBadRequest)  
		return  
	}  
  
	// Input validation  
	if location.Name == "" {  
		log.Printf("Name is missing")  
		http.Error(w, "Name is missing", http.StatusBadRequest)  
		return  
	}  
	if location.Address == "" {  
		log.Printf("Address is missing")  
		http.Error(w, "Address is missing", http.StatusBadRequest)  
		return  
	}  
  
	// Create a new location in the database  
	if err := config.DB.Create(&location).Error; err != nil {  
		log.Printf("Failed to create location: %v", err)  
		http.Error(w, "Failed to create location", http.StatusInternalServerError)  
		return  
	}  
  
	// Log successful creation  
	log.Printf("Location created successfully: ID=%d, Name=%s", location.ID, location.Name)  
  
	// Prepare the response with only id, name, address, and description  
	response := struct {  
		ID          uint   `json:"id"`  
		Name        string `json:"name"`  
		Address     string `json:"address"`  
		Description string `json:"description"`  
	}{  
		ID:          location.ID,  
		Name:        location.Name,  
		Address:     location.Address,  
		Description: location.Description,  
	}  
  
	// Return the newly created location data  
	w.WriteHeader(http.StatusCreated)  
	json.NewEncoder(w).Encode(response)  
}  


// UpdateLocation handles PUT requests to update existing location data
func UpdateLocation(w http.ResponseWriter, r *http.Request) {
    // Set CORS headers
    if config.SetAccessControlHeaders(w, r) {
        return // If this is a preflight request, exit the function
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

    // Parse the request body to extract updated location details
    var updatedLocation model.Location
    if err := json.NewDecoder(r.Body).Decode(&updatedLocation); err != nil {
        log.Printf("Failed to decode request body: %v", err)
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate the ID
    if updatedLocation.ID == 0 {
        http.Error(w, "ID is required", http.StatusBadRequest)
        return
    }

    // Input validation
    if updatedLocation.Name == "" {
        log.Printf("Name is missing")
        http.Error(w, "Name is missing", http.StatusBadRequest)
        return
    }
    if updatedLocation.Address == "" {
        log.Printf("Address is missing")
        http.Error(w, "Address is missing", http.StatusBadRequest)
        return
    }

    // Update the location in the database
    result := config.DB.Model(&model.Location{}).Where("id = ?", updatedLocation.ID).Updates(updatedLocation)
    if result.Error != nil {
        log.Printf("Failed to update location: %v", result.Error)
        http.Error(w, "Failed to update location", http.StatusInternalServerError)
        return
    }

    // Check if any rows were affected
    if result.RowsAffected == 0 {
        log.Printf("Location not found: ID=%d", updatedLocation.ID)
        http.Error(w, "Location not found", http.StatusNotFound)
        return
    }

    // Log successful update
    log.Printf("Location updated successfully: ID=%d", updatedLocation.ID)

    // Return success response
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Location updated successfully"})
}

 
// DeleteLocation handles DELETE requests to delete existing location data  
func DeleteLocation(w http.ResponseWriter, r *http.Request) {  
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
  
	// Parse the request body to extract the ID  
	var location model.Location  
	if err := json.NewDecoder(r.Body).Decode(&location); err != nil {  
		log.Printf("Failed to decode request body: %v", err)  
		http.Error(w, "Invalid request body", http.StatusBadRequest)  
		return  
	}  
  
	// Validate the ID  
	if location.ID == 0 {  
		http.Error(w, "ID is required", http.StatusBadRequest)  
		return  
	}  
  
	// Delete the location from the database  
	result := config.DB.Where("id = ?", location.ID).Delete(&model.Location{})  
	if result.Error != nil {  
		log.Printf("Failed to delete location: %v", result.Error)  
		http.Error(w, "Failed to delete location", http.StatusInternalServerError)  
		return  
	}  
  
	// Check if any rows were affected  
	if result.RowsAffected == 0 {  
		log.Printf("Location not found: ID=%d", location.ID)  
		http.Error(w, "Location not found", http.StatusNotFound)  
		return  
	}  
  
	// Log successful deletion  
	log.Printf("Location deleted successfully: ID=%d", location.ID)  
  
	// Return success response  
	w.WriteHeader(http.StatusOK)  
	json.NewEncoder(w).Encode(map[string]string{"message": "Location deleted successfully"})  
}