package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Register Handler
func Register(w http.ResponseWriter, r *http.Request) {
	// Periksa metode HTTP
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Please use POST.", http.StatusMethodNotAllowed)
		return
	}

	var requestData model.RequestData

	// Parse JSON request body
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid input. Please check your request data.", http.StatusBadRequest)
		return
	}

	// Validasi input
	if requestData.Password != requestData.ConfirmPassword {
		http.Error(w, "Passwords do not match", http.StatusBadRequest)
		return
	}

	if requestData.Email == "" || requestData.Username == "" || requestData.Password == "" || requestData.Role == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Periksa apakah email atau username sudah digunakan
	var existingUser model.User
	result := config.DB.Where("email = ? OR username = ?", requestData.Email, requestData.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		http.Error(w, "Email or username already exists. Please use a different one.", http.StatusBadRequest)
		return
	} else if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		http.Error(w, "Failed to validate user data. Please try again later.", http.StatusInternalServerError)
		return
	}

	// Cari role di tabel roles
	var role model.Role
	if err := config.DB.Where("name = ?", requestData.Role).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "Invalid role. Role must be either 'user' or 'admin'.", http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to validate role. Please try again later.", http.StatusInternalServerError)
		}
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Simpan user ke database
	user := model.User{
		Email:    requestData.Email,
		Username: requestData.Username,
		Password: string(hashedPassword),
		RoleID:   role.ID,
	}

	if err := config.DB.Create(&user).Error; err != nil {
		http.Error(w, "Failed to register user. Please try again later.", http.StatusInternalServerError)
		return
	}

	// Ambil user yang baru dibuat beserta relasi role
	var newUser model.User
	if err := config.DB.Preload("Role").Where("id = ?", user.ID).First(&newUser).Error; err != nil {
		http.Error(w, "Failed to retrieve user data.", http.StatusInternalServerError)
		return
	}

	// Kirim respons sukses
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"user": map[string]interface{}{
			"email":    newUser.Email,
			"id":       newUser.ID,
			"username": newUser.Username,
			"role":     newUser.Role.Name, // Pastikan `Role.Name` diambil dengan `Preload`
		},
	})
}





// function login user dan admin
func Login(w http.ResponseWriter, r *http.Request) {
	// Validasi metode HTTP
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode input
	var loginInput model.LoginInput
	if err := json.NewDecoder(r.Body).Decode(&loginInput); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Cari pengguna berdasarkan email
	var user model.User
	if err := config.DB.Where("email = ?", loginInput.Email).First(&user).Error; err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Periksa password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginInput.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Buat token JWT
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := model.Claims{
		UserID: user.ID,
		Role:   user.Role.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.JwtKey))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Simpan token ke tabel active_tokens
	activeToken := model.ActiveToken{
		UserID:    user.ID,
		Token:     tokenString,
		ExpiresAt: expirationTime,
	}
	if err := config.DB.Create(&activeToken).Error; err != nil {
		http.Error(w, "Failed to save active token", http.StatusInternalServerError)
		return
	}

	// Kirim respons
	response := map[string]interface{}{
		"message": "Login successful",
		"user": map[string]interface{}{
			"id":       user.ID,
			"email":    user.Email,
			"username": user.Username,
			"role":     user.Role.Name,
		},
		"token": tokenString,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}



func Logout(w http.ResponseWriter, r *http.Request) {
    // Ambil token dari header Authorization
    token := r.Header.Get("Authorization")
    if token == "" {
        http.Error(w, "Token not provided", http.StatusUnauthorized)
        return
    }

    // Tambahkan token ke tabel blacklist
    blacklistedToken := model.BlacklistToken{
        Token:     token,
        ExpiresAt: time.Now().Add(24 * time.Hour), // Token kedaluwarsa dalam 24 jam
    }
    if err := config.DB.Create(&blacklistedToken).Error; err != nil {
        http.Error(w, "Failed to blacklist token", http.StatusInternalServerError)
        return
    }

    // Hapus token dari tabel active_tokens (opsional)
    config.DB.Where("token = ?", token).Delete(&model.ActiveToken{})

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":  "success",
        "message": "Logout successful, token blacklisted",
    })
}








