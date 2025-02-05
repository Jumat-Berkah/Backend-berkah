package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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

    // Query users dengan preload Role
    if err := config.DB.Preload("Role").Find(&users).Error; err != nil {
        log.Printf("Failed to retrieve users: %v", err)
        http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
        return
    }

    // Buat response structure yang sesuai dengan kebutuhan frontend
    type UserResponse struct {
        ID              uint   `json:"id"`
        Username        string `json:"username"`
        Email           string `json:"email"`
        Bio            string `json:"bio"`
        PreferredMasjid string `json:"preferred_masjid"`
        ProfilePicture  string `json:"profile_picture"`
        Role           struct {
            Name string `json:"name"`
        } `json:"role"`
    }

    // Convert users ke response format
    var response []UserResponse
    for _, user := range users {
        userResp := UserResponse{
            ID:              user.ID,
            Username:        user.Username,
            Email:           user.Email,
            Bio:            user.Bio,
            PreferredMasjid: user.PreferredMasjid,
            ProfilePicture:  user.ProfilePicture,
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

// upload gambarrr
const (
    MaxFileSize    = 20 * 1024 * 1024 // 20MB in bytes
    UploadDir      = "./uploads/profile-pictures"
    AllowedTypes   = ".jpg,.jpeg,.png,.gif"
)

func UploadProfilePicture(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Set response header
    w.Header().Set("Content-Type", "application/json")

    // Parse multipart form dengan maksimal ukuran 20MB
    if err := r.ParseMultipartForm(MaxFileSize); err != nil {
        http.Error(w, "File terlalu besar. Maksimal 20MB", http.StatusBadRequest)
        return
    }

    // Ambil file dari form
    file, header, err := r.FormFile("profile_picture")
    if err != nil {
        http.Error(w, "Gagal mengambil file", http.StatusBadRequest)
        return
    }
    defer file.Close()

    // Validasi ukuran file
    if header.Size > MaxFileSize {
        http.Error(w, "Ukuran file melebihi 20MB", http.StatusBadRequest)
        return
    }

    // Validasi tipe file
    ext := strings.ToLower(filepath.Ext(header.Filename))
    if !strings.Contains(AllowedTypes, ext) {
        http.Error(w, "Tipe file tidak diizinkan. Gunakan: "+AllowedTypes, http.StatusBadRequest)
        return
    }

    // Ambil user ID dari form
    userID := r.FormValue("user_id")
    if userID == "" {
        http.Error(w, "User ID diperlukan", http.StatusBadRequest)
        return
    }

    // Buat direktori jika belum ada
    if err := os.MkdirAll(UploadDir, 0755); err != nil {
        http.Error(w, "Gagal membuat direktori upload", http.StatusInternalServerError)
        return
    }

    // Generate nama file unik
    filename := fmt.Sprintf("%s_%d%s", userID, time.Now().UnixNano(), ext)
    filepath := filepath.Join(UploadDir, filename)

    // Buat file baru
    dst, err := os.Create(filepath)
    if err != nil {
        http.Error(w, "Gagal membuat file", http.StatusInternalServerError)
        return
    }
    defer dst.Close()

    // Copy file ke tujuan
    if _, err := io.Copy(dst, file); err != nil {
        http.Error(w, "Gagal menyimpan file", http.StatusInternalServerError)
        return
    }

    // Update URL gambar di database
    var user model.User
    if err := config.DB.First(&user, userID).Error; err != nil {
        http.Error(w, "User tidak ditemukan", http.StatusNotFound)
        return
    }

    // Generate URL untuk akses gambar
    imageURL := fmt.Sprintf("/uploads/profile-pictures/%s", filename)
    
    // Update profile_picture di database
    if err := config.DB.Model(&user).Update("profile_picture", imageURL).Error; err != nil {
        http.Error(w, "Gagal memperbarui database", http.StatusInternalServerError)
        return
    }

    // Kirim response sukses
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Foto profil berhasil diupload",
        "url": imageURL,
    })
}

// Fungsi untuk serve file statis
func ServeProfilePicture(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Ambil nama file dari URL
    filename := filepath.Base(r.URL.Path)
    filepath := filepath.Join(UploadDir, filename)

    // Cek apakah file ada
    if _, err := os.Stat(filepath); os.IsNotExist(err) {
        http.Error(w, "File tidak ditemukan", http.StatusNotFound)
        return
    }

    // Serve file
    http.ServeFile(w, r, filepath)
}