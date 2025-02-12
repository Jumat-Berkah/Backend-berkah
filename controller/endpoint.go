package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
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
	"gopkg.in/gomail.v2"
	"gorm.io/gorm"
)

// GetLocation handles GET requests to retrieve locations
func GetLocation(w http.ResponseWriter, r *http.Request) {
    // Set CORS headers
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Set content type to JSON
    w.Header().Set("Content-Type", "application/json")

    // Retrieve locations from the database
    var locations []model.Location
    if err := config.DB.Find(&locations).Error; err != nil {
        log.Printf("Failed to retrieve locations: %v", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Return the locations as JSON
    w.WriteHeader(http.StatusOK)
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
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Delete the location from the database
    if err := config.DB.Delete(&location, location.ID).Error; err != nil {
        log.Printf("Failed to delete location: %v", err)
        http.Error(w, "Failed to delete location", http.StatusInternalServerError)
        return
    }

    // Respond with success message
    w.WriteHeader(http.StatusNoContent) // 204 No Content
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

    // Query users dengan preload Role dan semua field yang diperlukan
    if err := config.DB.Preload("Role").Find(&users).Error; err != nil {
        log.Printf("Failed to retrieve users: %v", err)
        http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
        return
    }

    // Buat response structure yang lengkap sesuai model User
    type UserResponse struct {
        ID              uint      `json:"id"`
        Username        string    `json:"username"`
        Email           string    `json:"email"`
        FullName        string    `json:"full_name"`
        PhoneNumber     string    `json:"phone_number"`
        Address         string    `json:"address"`
        ProfilePicture  string    `json:"profile_picture"`
        PreferredMasjid string    `json:"preferred_masjid"`
        Bio            string    `json:"bio"`
        JoinDate       time.Time `json:"join_date"`
        Role           struct {
            ID   uint   `json:"id"`
            Name string `json:"name"`
        } `json:"role"`
    }

    // Convert users ke response format
    var response []UserResponse
    for _, user := range users {
        // Pastikan URL profile picture lengkap
        profilePicture := user.ProfilePicture
        if profilePicture != "" && !strings.HasPrefix(profilePicture, "http") {
            profilePicture = fmt.Sprintf("/uploads/profile-pictures/%s", profilePicture)
        }

        userResp := UserResponse{
            ID:              user.ID,
            Username:        user.Username,
            Email:           user.Email,
            FullName:        user.FullName,
            PhoneNumber:     user.PhoneNumber,
            Address:         user.Address,
            ProfilePicture:  profilePicture,
            PreferredMasjid: user.PreferredMasjid,
            Bio:            user.Bio,
            JoinDate:       user.JoinDate,
            Role: struct {
                ID   uint   `json:"id"`
                Name string `json:"name"`
            }{
                ID:   user.Role.ID,
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

    // Parse multipart form untuk menangani file upload
    if err := r.ParseMultipartForm(20 * 1024 * 1024); err != nil { // 20MB max
        http.Error(w, "Gagal memproses form", http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "application/json")

    // Ambil data profile dari form
    userID := r.FormValue("user_id")
    if userID == "" {
        http.Error(w, "User ID diperlukan", http.StatusBadRequest)
        return
    }

    // Ambil data user yang ada
    var user model.User
    if err := config.DB.First(&user, userID).Error; err != nil {
        http.Error(w, "User tidak ditemukan", http.StatusNotFound)
        return
    }

    // Update fields dasar
    updates := map[string]interface{}{
        "username":         r.FormValue("username"),
        "email":           r.FormValue("email"),
        "full_name":       r.FormValue("full_name"),
        "phone_number":    r.FormValue("phone_number"),
        "address":         r.FormValue("address"),
        "preferred_masjid": r.FormValue("preferred_masjid"),
        "bio":             r.FormValue("bio"),
    }

    // Handle profile picture jika ada
    file, header, err := r.FormFile("profile_picture")
    if err == nil { // Jika ada file yang diupload
        defer file.Close()

        // Validasi tipe file
        if !strings.HasPrefix(header.Header.Get("Content-Type"), "image/") {
            http.Error(w, "File harus berupa gambar", http.StatusBadRequest)
            return
        }

        // Validasi ukuran file (max 20MB)
        if header.Size > 20*1024*1024 {
            http.Error(w, "Ukuran file terlalu besar (max 20MB)", http.StatusBadRequest)
            return
        }

        // Generate nama file unik
        ext := filepath.Ext(header.Filename)
        filename := fmt.Sprintf("%s_%d%s", userID, time.Now().UnixNano(), ext)
        uploadPath := filepath.Join("uploads/profile-pictures", filename)

        // Buat direktori jika belum ada
        if err := os.MkdirAll("uploads/profile-pictures", 0755); err != nil {
            log.Printf("Error creating directory: %v", err)
            http.Error(w, "Gagal menyimpan file", http.StatusInternalServerError)
            return
        }

        // Buat file baru
        dst, err := os.Create(uploadPath)
        if err != nil {
            log.Printf("Error creating file: %v", err)
            http.Error(w, "Gagal menyimpan file", http.StatusInternalServerError)
            return
        }
        defer dst.Close()

        // Copy file ke tujuan
        if _, err := io.Copy(dst, file); err != nil {
            log.Printf("Error copying file: %v", err)
            http.Error(w, "Gagal menyimpan file", http.StatusInternalServerError)
            return
        }

        // Hapus file lama jika ada
        if user.ProfilePicture != "" {
            oldPath := filepath.Join(".", user.ProfilePicture)
            if err := os.Remove(oldPath); err != nil {
                log.Printf("Error removing old profile picture: %v", err)
            }
        }

        // Update path gambar di database
        updates["profile_picture"] = "/" + uploadPath
    }

    // Handle password update jika ada
    oldPassword := r.FormValue("old_password")
    newPassword := r.FormValue("new_password")
    if oldPassword != "" && newPassword != "" {
        if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
            http.Error(w, "Password lama tidak sesuai", http.StatusUnauthorized)
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
        if err != nil {
            log.Printf("Error hashing password: %v", err)
            http.Error(w, "Gagal memproses password baru", http.StatusInternalServerError)
            return
        }

        updates["password"] = string(hashedPassword)
    }

    // Lakukan update ke database
    result := config.DB.Model(&user).Updates(updates)
    if result.Error != nil {
        log.Printf("Error updating user: %v", result.Error)
        http.Error(w, "Gagal memperbarui profil", http.StatusInternalServerError)
        return
    }

    // Ambil data user yang sudah diupdate
    var updatedUser model.User
    if err := config.DB.First(&updatedUser, userID).Error; err != nil {
        log.Printf("Error fetching updated user: %v", err)
        http.Error(w, "Gagal mengambil data user terbaru", http.StatusInternalServerError)
        return
    }

    // Format response
    response := struct {
        Message string `json:"message"`
        User    struct {
            ID              uint   `json:"id"`
            Username        string `json:"username"`
            Email           string `json:"email"`
            FullName        string `json:"full_name"`
            PhoneNumber     string `json:"phone_number"`
            Address         string `json:"address"`
            PreferredMasjid string `json:"preferred_masjid"`
            Bio            string `json:"bio"`
            ProfilePicture  string `json:"profile_picture"`
        } `json:"user"`
    }{
        Message: "Profil berhasil diperbarui",
        User: struct {
            ID              uint   `json:"id"`
            Username        string `json:"username"`
            Email           string `json:"email"`
            FullName        string `json:"full_name"`
            PhoneNumber     string `json:"phone_number"`
            Address         string `json:"address"`
            PreferredMasjid string `json:"preferred_masjid"`
            Bio            string `json:"bio"`
            ProfilePicture  string `json:"profile_picture"`
        }{
            ID:              updatedUser.ID,
            Username:        updatedUser.Username,
            Email:           updatedUser.Email,
            FullName:        updatedUser.FullName,
            PhoneNumber:     updatedUser.PhoneNumber,
            Address:         updatedUser.Address,
            PreferredMasjid: updatedUser.PreferredMasjid,
            Bio:            updatedUser.Bio,
            ProfilePicture:  updatedUser.ProfilePicture,
        },
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
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

func SendResetPasswordEmail(email, token string) error {
	emailUser := os.Getenv("EMAIL_USER")
	emailPassword := os.Getenv("EMAIL_PASSWORD")
	from := emailUser
	to := email

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Reset Password")
	m.SetBody("text/plain", "Klik tautan berikut untuk mereset password Anda: https://jumatberkah.vercel.app/reset-password/new-password?token="+token) // Sesuaikan link domain Anda

	d := gomail.NewDialer("smtp.gmail.com", 587, from, emailPassword) // Konfigurasi Dialer Gmail
	// Anda bisa menambahkan konfigurasi TLS jika diperlukan (opsional, tapi sebaiknya dipertimbangkan untuk keamanan):
	// d.TLSConfig = &tls.Config{InsecureSkipVerify: true, ServerName: "smtp.gmail.com"}

	if err := d.DialAndSend(m); err != nil {
		log.Println("ERROR: Gagal mengirim email reset password ke:", email) // Tambahkan log error!
		log.Println("Detail error:", err) // Tambahkan detail error!
		return err
	}

	return nil
}
func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")

    var user model.User
    result := config.DB.Where("email = ?", email).First(&user)

    if result.Error != nil {
        if result.Error == gorm.ErrRecordNotFound {
            http.Error(w, "Email tidak ditemukan", http.StatusNotFound)
        } else {
            http.Error(w, "Terjadi kesalahan database", http.StatusInternalServerError)
        }
        return
    }

    userID := user.ID // Assuming you have user ID available
    email = user.Email // Assuming you have user email available
    token, err := helper.GenerateToken(userID, email)
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }
    user.ResetPasswordToken = token
    user.ResetPasswordExpiry = time.Now().Add(time.Hour)
    config.DB.Save(&user)

    // Define resetLink
    resetLink := fmt.Sprintf("https://jumatberkah.vercel.app/reset-password?token=%s", token)

    err = SendResetPasswordEmail(user.Email, resetLink)
    if err != nil {
        // Ubah penanganan error menjadi respons JSON
        w.Header().Set("Content-Type", "application/json") // Set header content type
        w.WriteHeader(http.StatusInternalServerError) // Tetapkan status code error (500 Internal Server Error)
        response := map[string]interface{}{
            "error":   "Gagal mengirim email reset password.",
            "message": "Terjadi masalah teknis saat mengirim email. Mohon coba lagi nanti.", // Pesan error yang lebih detail (opsional)
        }
        json.NewEncoder(w).Encode(response) // Kirim respons JSON
        return // Penting untuk keluar dari handler setelah mengirim error
    }

    w.Header().Set("Content-Type", "application/json") // Pastikan respons sukses juga JSON
    responseSuccess := map[string]string{
        "message": "Permintaan reset password berhasil dikirim. Silakan periksa email Anda.",
    }
    json.NewEncoder(w).Encode(responseSuccess)
}

// Handler untuk permintaan perubahan password baru
func NewPasswordHandler(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token") //Ambil token dari query parameter
    password := r.FormValue("password")

    var user model.User
    result := config.DB.Where("reset_password_token = ?", token).First(&user)

    if result.Error != nil {
        http.Error(w, "Token tidak valid", http.StatusBadRequest)
        return
    }

    if user.ResetPasswordExpiry.Before(time.Now()) {
        http.Error(w, "Token telah kadaluarsa", http.StatusBadRequest)
        return
    }

    hashedPassword, err := helper.HashPassword(password) // Hash password
    if err != nil {
        http.Error(w, "Gagal hash password", http.StatusInternalServerError)
        return
    }

    user.Password = hashedPassword
    user.ResetPasswordToken = ""
    user.ResetPasswordExpiry = time.Time{}
    config.DB.Save(user)

    http.Redirect(w, r, "/success", http.StatusSeeOther) // Redirect ke halaman sukses
}