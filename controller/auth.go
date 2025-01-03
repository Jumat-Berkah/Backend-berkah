package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

// Register Handler
func Register(w http.ResponseWriter, r *http.Request) {
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

	// Cari role di tabel roles
	var role model.Role
	if err := config.DB.Where("name = ?", requestData.Role).First(&role).Error; err != nil {
		http.Error(w, "Invalid role. Role must be either 'user' or 'admin'.", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Simpan ke database
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

	// Kirim respons sukses
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User registered successfully",
		"role":    role.Name,
	})
}




// Login Handler
func Login(w http.ResponseWriter, r *http.Request) {
	var input model.LoginInput
	var user model.User

	// Parse JSON request body
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Cari user berdasarkan email
	if err := config.DB.Preload("Role").Where("email = ?", input.Email).First(&user).Error; err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Cek password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Redirect ke dashboard berdasarkan role
	var dashboard string
	if user.Role.Name == "admin" && r.URL.Path == "/api/admin/login" {
		dashboard = "/admin/dashboard"
	} else if user.Role.Name == "user" && r.URL.Path == "/api/user/login" {
		dashboard = "/user/dashboard"
	} else {
		http.Error(w, "Access denied. Role mismatch for this route.", http.StatusForbidden)
		return
	}

	// Buat token JWT
	expirationTime := time.Now().Add(24 * time.Hour) // Token berlaku selama 24 jam
	claims := &model.Claims{
		UserID: user.ID,
		Role:   user.Role.Name, // Role dari tabel roles
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.JwtKey))
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Kirim respons token, role, dan dashboard
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Login successful",
		"user_id":   user.ID,
		"role":      user.Role.Name,
		"token":     tokenString,
		"dashboard": dashboard,
	})
}



