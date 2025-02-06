package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
	"Backend-berkah/model"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
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

func HandleAuth0Login(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    state := config.GenerateStateString()
    // Set cookie untuk state verification
    http.SetCookie(w, &http.Cookie{
        Name:     "auth_state",
        Value:    state,
        MaxAge:   int(time.Hour.Seconds()),
        HttpOnly: true,
        Secure:   true,
        Path:     "/",
    })

    // Redirect ke Auth0 untuk autentikasi
    authURL := fmt.Sprintf(
        "https://%s/authorize?"+
            "response_type=code&"+
            "client_id=%s&"+
            "redirect_uri=%s&"+
            "scope=openid profile email&"+
            "state=%s",
        config.Auth0Config.Domain,
        config.Auth0Config.ClientID,
        url.QueryEscape(config.Auth0Config.RedirectURL),
        state,
    )

    http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func HandleAuth0Callback(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Verifikasi state
    stateCookie, err := r.Cookie("auth_state")
    if err != nil {
        log.Printf("Error getting state cookie: %v", err)
        http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=state_missing", http.StatusTemporaryRedirect)
        return
    }

    state := r.URL.Query().Get("state")
    if state != stateCookie.Value {
        log.Printf("Invalid state parameter")
        http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=invalid_state", http.StatusTemporaryRedirect)
        return
    }

    // Dapatkan code
    code := r.URL.Query().Get("code")
    if code == "" {
        log.Printf("No code received")
        http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=no_code", http.StatusTemporaryRedirect)
        return
    }

    // Exchange code untuk token
    tokenURL := fmt.Sprintf("https://%s/oauth/token", config.Auth0Config.Domain)
    tokenData := url.Values{}
    tokenData.Set("grant_type", "authorization_code")
    tokenData.Set("client_id", config.Auth0Config.ClientID)
    tokenData.Set("client_secret", config.Auth0Config.ClientSecret)
    tokenData.Set("code", code)
    tokenData.Set("redirect_uri", config.Auth0Config.RedirectURL)

    resp, err := http.PostForm(tokenURL, tokenData)
    if err != nil {
        log.Printf("Error exchanging code for token: %v", err)
        http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=token_exchange", http.StatusTemporaryRedirect)
        return
    }
    defer resp.Body.Close()

    var tokenResponse struct {
        AccessToken string `json:"access_token"`
        IDToken    string `json:"id_token"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
        log.Printf("Error decoding token response: %v", err)
        http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=token_decode", http.StatusTemporaryRedirect)
        return
    }

    // Dapatkan info user dari Auth0
    userInfoURL := fmt.Sprintf("https://%s/userinfo", config.Auth0Config.Domain)
    req, _ := http.NewRequest("GET", userInfoURL, nil)
    req.Header.Add("Authorization", "Bearer "+tokenResponse.AccessToken)

    client := &http.Client{}
    userInfoResp, err := client.Do(req)
    if err != nil {
        log.Printf("Error getting user info: %v", err)
        http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=userinfo", http.StatusTemporaryRedirect)
        return
    }
    defer userInfoResp.Body.Close()

    var userInfo struct {
        Email    string `json:"email"`
        Name     string `json:"name"`
        Picture  string `json:"picture"`
        Sub      string `json:"sub"`
    }

    if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfo); err != nil {
        log.Printf("Error decoding user info: %v", err)
        http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=userinfo_decode", http.StatusTemporaryRedirect)
        return
    }

    // Simpan atau update user di database
    var user model.User
    result := config.DB.Where("email = ?", userInfo.Email).First(&user)
    if result.Error != nil {
        // Buat user baru
        user = model.User{
            Email:    userInfo.Email,
            Username: userInfo.Name,
            RoleID:   1, // User biasa
        }
        if err := config.DB.Create(&user).Error; err != nil {
            log.Printf("Error creating user: %v", err)
            http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=db_error", http.StatusTemporaryRedirect)
            return
        }
    }

    // Generate JWT untuk aplikasi kita
    token, err := helper.GenerateToken(user.ID, "user")
    if err != nil {
        log.Printf("Error generating token: %v", err)
        http.Redirect(w, r, "https://jumatberkah.vercel.app/auth/login.html?error=jwt_error", http.StatusTemporaryRedirect)
        return
    }

    // Redirect ke frontend dengan token
    redirectURL := fmt.Sprintf("https://jumatberkah.vercel.app/?token=%s", token)
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
    
    // Untuk Auth0, kita hanya perlu menangani cleanup di database
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













