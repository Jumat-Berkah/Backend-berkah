package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// GetLocation handles GET requests to retrieve locations
func GetLocation(w http.ResponseWriter, r *http.Request) {    
    // Set CORS headers    
    if config.SetAccessControlHeaders(w, r) {    
        return   
    }    

    // Set content type to JSON
    w.Header().Set("Content-Type", "application/json")

    // Retrieve up to 15 locations from the database  
    var locations []model.Location  
    if err := config.DB.Find(&locations).Error; err != nil {  
        log.Printf("Failed to retrieve locations: %v", err)
        http.Error(w, "Could not retrieve locations", http.StatusInternalServerError)  
        return  
    }  

    // Return the locations as JSON  
    json.NewEncoder(w).Encode(locations)  
}

// CreateLocation handles POST requests to create new location data  
func CreateLocation(w http.ResponseWriter, r *http.Request) {  
    // Set CORS headers  
    if config.SetAccessControlHeaders(w, r) {  
        return
    }  
  
    // Set content type to JSON  
    w.Header().Set("Content-Type", "application/json")  
  
    // Parse the request body
    var location model.Location  
    if err := json.NewDecoder(r.Body).Decode(&location); err != nil {  
        log.Printf("Failed to decode request body: %v", err)  
        http.Error(w, "Invalid request body", http.StatusBadRequest)  
        return  
    }  
  
    // Input validation  
    if location.Name == "" || location.Address == "" {  
        log.Printf("Missing required fields")  
        http.Error(w, "Name and address are required", http.StatusBadRequest)  
        return  
    }  
  
    // Create location in database
    if err := config.DB.Create(&location).Error; err != nil {  
        log.Printf("Failed to create location: %v", err)  
        http.Error(w, "Failed to create location", http.StatusInternalServerError)  
        return  
    }  
  
    // Return success response
    w.WriteHeader(http.StatusCreated)  
    json.NewEncoder(w).Encode(location)  
}  

// UpdateLocation handles PUT requests to update existing location data
func UpdateLocation(w http.ResponseWriter, r *http.Request) {
    // Set CORS headers
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Set content type to JSON
    w.Header().Set("Content-Type", "application/json")

    // Parse request body
    var location model.Location
    if err := json.NewDecoder(r.Body).Decode(&location); err != nil {
        log.Printf("Failed to decode request body: %v", err)
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate required fields
    if location.ID == 0 {
        http.Error(w, "Location ID is required", http.StatusBadRequest)
        return
    }
    if location.Name == "" || location.Address == "" {
        http.Error(w, "Name and address are required", http.StatusBadRequest)
        return
    }

    // Update location in database
    result := config.DB.Model(&model.Location{}).Where("id = ?", location.ID).Updates(location)
    if result.Error != nil {
        log.Printf("Failed to update location: %v", result.Error)
        http.Error(w, "Failed to update location", http.StatusInternalServerError)
        return
    }

    if result.RowsAffected == 0 {
        http.Error(w, "Location not found", http.StatusNotFound)
        return
    }

    // Return success response
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Location updated successfully"})
}

// DeleteLocation handles DELETE requests to delete existing location data  
func DeleteLocation(w http.ResponseWriter, r *http.Request) {  
    // Set CORS headers  
    if config.SetAccessControlHeaders(w, r) {  
        return
    }  
  
    // Set content type to JSON  
    w.Header().Set("Content-Type", "application/json")  
  
    // Parse request body
    var location model.Location  
    if err := json.NewDecoder(r.Body).Decode(&location); err != nil {  
        log.Printf("Failed to decode request body: %v", err)  
        http.Error(w, "Invalid request body", http.StatusBadRequest)  
        return  
    }  
  
    // Validate ID  
    if location.ID == 0 {  
        http.Error(w, "Location ID is required", http.StatusBadRequest)  
        return  
    }  
  
    // Delete location from database
    result := config.DB.Delete(&model.Location{}, location.ID)  
    if result.Error != nil {  
        log.Printf("Failed to delete location: %v", result.Error)  
        http.Error(w, "Failed to delete location", http.StatusInternalServerError)  
        return  
    }  
  
    if result.RowsAffected == 0 {  
        http.Error(w, "Location not found", http.StatusNotFound)  
        return  
    }  
  
    // Return success response
    w.WriteHeader(http.StatusOK)  
    json.NewEncoder(w).Encode(map[string]string{"message": "Location deleted successfully"})  
}

// manage user
// GetUsers handles GET requests to retrieve all users
func GetUsers(w http.ResponseWriter, r *http.Request) {
    // Set CORS headers
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Set content type to JSON
    w.Header().Set("Content-Type", "application/json")

    var users []model.User

    // Query users with their roles using Preload
    if err := config.DB.Preload("Role").Find(&users).Error; err != nil {
        log.Printf("Failed to retrieve users: %v", err)
        http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
        return
    }

    // Create response structure that only includes needed fields
    type UserResponse struct {
        ID       uint   `json:"id"`
        Username string `json:"username"`
        Email    string `json:"email"`
        Role     struct {
            Name string `json:"name"`
        } `json:"role"`
    }

    // Convert users to response format
    var response []UserResponse
    for _, user := range users {
        userResp := UserResponse{
            ID:       user.ID,
            Username: user.Username,
            Email:    user.Email,
            Role: struct {
                Name string `json:"name"`
            }{
                Name: user.Role.Name,
            },
        }
        response = append(response, userResp)
    }

    // Return the users as JSON
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}

// UpdateUser handles PUT requests to update existing user data
func UpdateUser(w http.ResponseWriter, r *http.Request) {
    // Set CORS headers
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Set content type to JSON
    w.Header().Set("Content-Type", "application/json")

    // Parse request body
    var updatedUser model.User
    if err := json.NewDecoder(r.Body).Decode(&updatedUser); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate required fields
    if updatedUser.ID == 0 {
        http.Error(w, "User ID is required", http.StatusBadRequest)
        return
    }

    // Update user in database
    result := config.DB.Model(&model.User{}).Where("id = ?", updatedUser.ID).Updates(map[string]interface{}{
        "username": updatedUser.Username,
        "email":    updatedUser.Email,
        "role_id":  updatedUser.RoleID,
    })

    if result.Error != nil {
        log.Printf("Failed to update user: %v", result.Error)
        http.Error(w, "Failed to update user", http.StatusInternalServerError)
        return
    }

    if result.RowsAffected == 0 {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Return success response
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

// DeleteUser handles DELETE requests to delete existing user data
func DeleteUser(w http.ResponseWriter, r *http.Request) {
    // Set CORS headers
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Set content type to JSON
    w.Header().Set("Content-Type", "application/json")

    // Parse request body to get user ID
    var user model.User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate user ID
    if user.ID == 0 {
        http.Error(w, "User ID is required", http.StatusBadRequest)
        return
    }

    // Delete user from database
    result := config.DB.Delete(&model.User{}, user.ID)
    if result.Error != nil {
        log.Printf("Failed to delete user: %v", result.Error)
        http.Error(w, "Failed to delete user", http.StatusInternalServerError)
        return
    }

    if result.RowsAffected == 0 {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Return success response
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}
// profile 
func UpdateProfile(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    w.Header().Set("Content-Type", "application/json")

    var updatedProfile model.UpdatedProfile

    if err := json.NewDecoder(r.Body).Decode(&updatedProfile); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var user model.User
    if err := config.DB.First(&user, updatedProfile.UserID).Error; err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Update user fields
    user.Username = updatedProfile.Username
    user.Email = updatedProfile.Email
    user.FullName = updatedProfile.FullName
    user.PhoneNumber = updatedProfile.PhoneNumber
    user.Address = updatedProfile.Address
    user.PreferredMasjid = updatedProfile.PreferredMasjid
    user.Bio = updatedProfile.Bio

    // Handle password update if provided
    if updatedProfile.OldPassword != "" && updatedProfile.NewPassword != "" {
        if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(updatedProfile.OldPassword)); err != nil {
            http.Error(w, "Password lama tidak sesuai", http.StatusUnauthorized)
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updatedProfile.NewPassword), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, "Gagal mengenkripsi password", http.StatusInternalServerError)
            return
        }
        user.Password = string(hashedPassword)
    }

    if err := config.DB.Save(&user).Error; err != nil {
        http.Error(w, "Gagal memperbarui profil", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{
        "message": "Profil berhasil diperbarui",
    })
}