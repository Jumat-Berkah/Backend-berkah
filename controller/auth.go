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




func Login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Decode JSON input ke LoginInput
    var loginInput model.LoginInput
    err := json.NewDecoder(r.Body).Decode(&loginInput)
    if err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Cari pengguna berdasarkan email
    var user model.User
    result := config.DB.Preload("Role").Where("email = ?", loginInput.Email).First(&user)
    if result.Error != nil {
        http.Error(w, "Invalid email or password", http.StatusUnauthorized)
        return
    }

    // Cocokkan password
    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginInput.Password))
    if err != nil {
        http.Error(w, "Invalid email or password", http.StatusUnauthorized)
        return
    }

    // Periksa apakah role sesuai
    if user.Role.Name != loginInput.Role {
        http.Error(w, "Role mismatch", http.StatusUnauthorized)
        return
    }

    // Buat token JWT
    claims := model.Claims{
        UserID: user.ID,
        Role:   user.Role.Name,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Token berlaku selama 24 jam
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString([]byte(config.JwtKey))
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    // Kirim response dengan token
    response := map[string]interface{}{
        "user": map[string]interface{}{
            "id":       user.ID,
            "email":    user.Email,
            "username": user.Username,
            "role":     user.Role.Name,
        },
        "token": tokenString,
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}





