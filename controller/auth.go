package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
	"Backend-berkah/model"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func Register(w http.ResponseWriter, r *http.Request) {
    // Ensure the HTTP method is POST
    if r.Method != http.MethodPost {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusMethodNotAllowed)
        json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
        return
    }

    // Decode the request body
    var newUser model.User
    if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
        log.Printf("Invalid request payload: %v", err)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
        return
    }

    // Validate input
    if newUser.Email == "" || newUser.Password == "" || newUser.Username == "" {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Email, username, and password are required"})
        return
    }

    // Check if the user already exists
    var existingUser model.User
    if err := config.DB.Where("email = ? OR username = ?", newUser.Email, newUser.Username).First(&existingUser).Error; err == nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Email or username already exists"})
        return
    }

    // Hash the password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("Error hashing password: %v", err)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Could not hash password"})
        return
    }
    newUser.Password = string(hashedPassword)

    // Set the role ID (assuming user role ID is 1)
    newUser.RoleID = 1 // Adjust this based on your role management

    // Save the user to the database
    if err := config.DB.Create(&newUser).Error; err != nil {
        log.Printf("Error saving user to database: %v", err)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Could not register user"})
        return
    }

    // Respond with success, including the username
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "User registered successfully",
        "user":    newUser.Username, // Return the username
    })
}

// untuk handle login function
func Login(w http.ResponseWriter, r *http.Request) {
    // Validate HTTP method
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Decode input
    var loginInput model.LoginInput
    if err := json.NewDecoder(r.Body).Decode(&loginInput); err != nil {
        log.Printf("Invalid request payload: %v", err)
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Validate input
    if loginInput.Email == "" || loginInput.Password == "" {
        http.Error(w, "Email and password are required", http.StatusBadRequest)
        return
    }

    // Validate user credentials
    user, err := helper.ValidateUser(loginInput.Email, loginInput.Password)
    if err != nil {
        log.Printf("Invalid credentials: %v", err)
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Fetch the role based on role_id
    var role model.Role
    if err := config.DB.First(&role, user.RoleID).Error; err != nil {
        log.Printf("Error fetching role: %v", err)
        http.Error(w, "Could not fetch user role", http.StatusInternalServerError)
        return
    }

    // Generate JWT token
    tokenString, err := helper.GenerateToken(user.ID, role.Name)
    if err != nil {
        log.Printf("Error generating token: %v", err)
        http.Error(w, "Could not create token", http.StatusInternalServerError)
        return
    }

    // Return the token and user information
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "token": tokenString,
        "user": map[string]interface{}{
            "id":   user.ID,
            "role": role.Name, // Include the role name
        },
    })
}

func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Generate state string untuk keamanan
    state := config.GenerateStateString()
    
    // Simpan state ke session atau cookie
    // Contoh menggunakan cookie:
    http.SetCookie(w, &http.Cookie{
        Name:     "oauthstate",
        Value:    state,
        Expires:  time.Now().Add(10 * time.Minute),
        HttpOnly: true,
        Secure:   true,
        Path:     "/",
        Domain:   "jumatberkah.vercel.app",
    })

    // Redirect ke halaman consent Google
    url := config.GoogleOauthConfig.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Ambil state dari cookie
    oauthCookie, err := r.Cookie("oauthstate")
    if err != nil {
        http.Error(w, "State cookie not found", http.StatusBadRequest)
        return
    }

    if r.FormValue("state") != oauthCookie.Value {
        http.Error(w, "Invalid oauth state", http.StatusBadRequest)
        return
    }

    // Exchange authorization code dengan token
    token, err := config.GoogleOauthConfig.Exchange(r.Context(), r.FormValue("code"))
    if err != nil {
        http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Ambil info user dari Google
    client := config.GoogleOauthConfig.Client(r.Context(), token)
    userInfo, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
    if err != nil {
        http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer userInfo.Body.Close()

    var googleUser struct {
        Email string `json:"email"`
        Name  string `json:"name"`
    }

    if err := json.NewDecoder(userInfo.Body).Decode(&googleUser); err != nil {
        http.Error(w, "Failed to decode user info: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Cek apakah user sudah ada di database
    var user model.User
    result := config.DB.Where("email = ?", googleUser.Email).First(&user)
    
    if result.Error != nil {
        // Jika user belum ada, buat user baru
        user = model.User{
            Email:    googleUser.Email,
            Username: googleUser.Name,
            RoleID:   1, // Role user biasa
        }
        
        if err := config.DB.Create(&user).Error; err != nil {
            http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
            return
        }
    }

     // Generate JWT token
     jwtToken, err := helper.GenerateToken(user.ID, user.Role.Name)
     if err != nil {
         http.Error(w, "Failed to generate token: "+err.Error(), http.StatusInternalServerError)
         return
     }
 
     // Tentukan redirect URL berdasarkan role
     var redirectURL string
     if user.Role.Name == "admin" {
         redirectURL = fmt.Sprintf("https://jumatberkah.vercel.app/admin/admin.html?token=%s", jwtToken)
     } else {
         redirectURL = fmt.Sprintf("https://jumatberkah.vercel.app/?token=%s", jwtToken)
     }
 
     // Redirect ke homepage
     http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
 }

 // ResetPassword menangani permintaan reset password
func ResetPassword(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Pastikan metode yang digunakan adalah POST
    if r.Method != http.MethodPost {
        http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
        return
    }

    // Decode request body
    var resetRequest struct {
        Email string `json:"email"`
    }

    if err := json.NewDecoder(r.Body).Decode(&resetRequest); err != nil {
        http.Error(w, "Format request tidak valid", http.StatusBadRequest)
        return
    }

    // Cari user berdasarkan email
    var user model.User
    if err := config.DB.Where("email = ?", resetRequest.Email).First(&user).Error; err != nil {
        http.Error(w, "Email tidak ditemukan", http.StatusNotFound)
        return
    }

    // Generate token reset password yang akan expired dalam 1 jam
    resetToken := helper.GenerateResetToken()
    expiryTime := time.Now().Add(1 * time.Hour)

    // Simpan token dan waktu expired ke database
    user.ResetToken = resetToken
    user.ResetTokenExpiry = &expiryTime

    if err := config.DB.Save(&user).Error; err != nil {
        http.Error(w, "Gagal menyimpan token reset", http.StatusInternalServerError)
        return
    }

    // Kirim response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Link reset password telah dikirim ke email Anda",
        "token": resetToken,
    })
}

// UpdatePassword menangani pembaruan password setelah reset
func UpdatePassword(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
        return
    }

    var updateRequest model.UpdatePasswordRequest

    if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
        http.Error(w, "Format request tidak valid", http.StatusBadRequest)
        return
    }

    // Validasi password baru
    if len(updateRequest.NewPassword) < 6 {
        http.Error(w, "Password harus minimal 6 karakter", http.StatusBadRequest)
        return
    }

    // Cari user berdasarkan token reset
    var user model.User
    if err := config.DB.Where("reset_token = ?", updateRequest.Token).First(&user).Error; err != nil {
        http.Error(w, "Token reset tidak valid", http.StatusBadRequest)
        return
    }

    // Cek apakah token sudah expired
    if user.ResetTokenExpiry == nil || time.Now().After(*user.ResetTokenExpiry) {
        http.Error(w, "Token reset sudah expired", http.StatusBadRequest)
        return
    }

    // Hash password baru
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateRequest.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Gagal memproses password baru", http.StatusInternalServerError)
        return
    }

    // Update password dan hapus token reset
    user.Password = string(hashedPassword)
    user.ResetToken = ""
    user.ResetTokenExpiry = nil

    if err := config.DB.Save(&user).Error; err != nil {
        http.Error(w, "Gagal memperbarui password", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Password berhasil diperbarui",
    })
}

func Logout(w http.ResponseWriter, r *http.Request) {
    // Set header
    w.Header().Set("Content-Type", "application/json")
    
    // Ambil token dari header
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        helper.WriteResponse(w, http.StatusBadRequest, map[string]interface{}{
            "error": "No token provided",
        })
        return
    }

    // Hapus token dari whitelist atau invalidate token jika menggunakan sistem seperti itu
    // Untuk kasus sederhana, client side akan menghapus token

    // Update last_logout di database jika diperlukan
    userID := r.Context().Value("userID").(uint)
    if err := config.DB.Model(&model.User{}).Where("id = ?", userID).
        Update("last_logout", time.Now()).Error; err != nil {
        helper.WriteResponse(w, http.StatusInternalServerError, map[string]interface{}{
            "error": "Failed to update logout time",
        })
        return
    }

    helper.WriteResponse(w, http.StatusOK, map[string]interface{}{
        "message": "Successfully logged out",
    })
}













