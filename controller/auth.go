package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
	"Backend-berkah/model"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

// Register handles user registration (only for user role)
func Register(w http.ResponseWriter, r *http.Request) {        
    // Ensure the HTTP method is POST        
    if r.Method != http.MethodPost {        
        w.Header().Set("Content-Type", "application/json")        
        w.WriteHeader(http.StatusMethodNotAllowed)        
        json.NewEncoder(w).Encode(map[string]string{        
            "message": "Method not allowed. Please use POST.",        
        })        
        return        
    }        
  
    var requestData model.RequestData        
  
    // Parse JSON request body        
    if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {        
        log.Printf("Invalid request data: %v", err)        
        w.Header().Set("Content-Type", "application/json")        
        w.WriteHeader(http.StatusBadRequest)        
        json.NewEncoder(w).Encode(map[string]string{        
            "message": "Invalid input. Please check your request data.",        
        })        
        return        
    }        
  
    // Validate input          
	if requestData.Password != requestData.ConfirmPassword {          
    w.Header().Set("Content-Type", "application/json")          
    w.WriteHeader(http.StatusBadRequest)          
    json.NewEncoder(w).Encode(map[string]string{          
        "message": "Passwords do not match.",          
    })          
    return          
}          
   
  
    if requestData.Email == "" || requestData.Username == "" || requestData.Password == "" {        
        w.Header().Set("Content-Type", "application/json")        
        w.WriteHeader(http.StatusBadRequest)        
        json.NewEncoder(w).Encode(map[string]string{        
            "message": "All fields are required.",        
        })        
        return        
    }        
  
    // Check if email or username already exists        
    var existingUser model.User        
    if err := config.DB.Where("email = ? OR username = ?", requestData.Email, requestData.Username).First(&existingUser).Error; err == nil {        
        log.Printf("User already exists with email: %s or username: %s", requestData.Email, requestData.Username)        
        w.Header().Set("Content-Type", "application/json")        
        w.WriteHeader(http.StatusBadRequest)        
        json.NewEncoder(w).Encode(map[string]string{        
            "message": "Email or username already exists. Please use a different one.",        
        })        
        return        
    }        
  
    // Hash password        
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)        
    if err != nil {        
        log.Printf("Failed to hash password: %v", err)        
        w.Header().Set("Content-Type", "application/json")        
        w.WriteHeader(http.StatusInternalServerError)        
        json.NewEncoder(w).Encode(map[string]string{        
            "message": "Failed to hash password.",        
        })        
        return        
    }        
  
    // Save user to database with default role_id = 2 (user)        
    user := model.User{        
        Email:    requestData.Email,        
        Username: requestData.Username,        
        Password: string(hashedPassword),        
        RoleID:   2, // Default role for regular users        
    }        
  
    if err := config.DB.Create(&user).Error; err != nil {        
        log.Printf("Failed to create user: %v", err)        
        w.Header().Set("Content-Type", "application/json")        
        w.WriteHeader(http.StatusInternalServerError)        
        json.NewEncoder(w).Encode(map[string]string{        
            "message": "Failed to register user. Please try again later.",        
        })        
        return        
    }        
  
    // Send success response        
    w.Header().Set("Content-Type", "application/json")        
    w.WriteHeader(http.StatusCreated)        
    json.NewEncoder(w).Encode(map[string]interface{}{        
        "message": "User registered successfully",        
        "user": map[string]interface{}{        
            "id":       user.ID,        
            "email":    user.Email,        
            "username": user.Username,        
            "role_id":  user.RoleID, // Include role ID in the response        
        },        
    })        
}  



  
// Login handles user login  
func Login(w http.ResponseWriter, r *http.Request) {  
	// Validasi metode HTTP  
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
  
	// Validasi input  
	if loginInput.Email == "" || loginInput.Password == "" {  
		http.Error(w, "Email and password are required", http.StatusBadRequest)  
		return  
	}  
  
	// Cari pengguna berdasarkan email  
	var user model.User  
	if err := config.DB.Preload("Role").Where("email = ?", loginInput.Email).First(&user).Error; err != nil {  
		log.Printf("User not found with email: %s", loginInput.Email)  
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)  
		return  
	}  
  
	// Periksa password  
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginInput.Password)); err != nil {  
		log.Printf("Invalid password for email: %s", loginInput.Email)  
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)  
		return  
	}  
  
	// Periksa apakah role valid  
	if user.Role.ID == 0 {  
		log.Printf("Role not found for user ID: %d", user.ID)  
		http.Error(w, "User role not found. Please contact support.", http.StatusUnauthorized)  
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
		log.Printf("Failed to generate token for user ID: %d, error: %v", user.ID, err)  
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
		log.Printf("Failed to save active token for user ID: %d, error: %v", user.ID, err)  
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
			"role_id":  user.Role.ID, // Menambahkan role_id ke respons  
		},  
		"token": tokenString,  
	}  
	w.Header().Set("Content-Type", "application/json")  
	w.WriteHeader(http.StatusOK)  
	json.NewEncoder(w).Encode(response)  
  
	log.Printf("User logged in successfully: ID=%d, email=%s, role=%s", user.ID, user.Email, user.Role.Name)  
}  
  
// Logout handles user logout  
func Logout(w http.ResponseWriter, r *http.Request) {  
	// Ambil token dari header Authorization  
	tokenString, err := helper.GetTokenFromHeader(r)
	if err != nil {
		log.Printf("Token error: %v", err)  
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)  
		return  
	}  
  
	// Periksa apakah token ada di blacklist  
	if helper.IsTokenBlacklisted(tokenString) {  
		log.Printf("Token is already blacklisted: %v", tokenString)  
		http.Error(w, "Unauthorized: Token has been blacklisted", http.StatusUnauthorized)  
		return  
	}  
  
	// Simpan token ke tabel blacklist_tokens  
	blacklistToken := model.BlacklistToken{  
		Token:     tokenString,  
		ExpiresAt: time.Now().Add(24 * time.Hour), // Token kedaluwarsa dalam 24 jam  
	}  
	if err := config.DB.Create(&blacklistToken).Error; err != nil {  
		log.Printf("Failed to blacklist token: %v", err)  
		http.Error(w, "Failed to blacklist token", http.StatusInternalServerError)  
		return  
	}  
  
	// Hapus token dari tabel active_tokens  
	if err := config.DB.Where("token = ?", tokenString).Delete(&model.ActiveToken{}).Error; err != nil {  
		log.Printf("Failed to delete token from active_tokens: %v", err)  
		http.Error(w, "Failed to delete active token", http.StatusInternalServerError)  
		return  
	}  
  
	w.Header().Set("Content-Type", "application/json")  
	json.NewEncoder(w).Encode(map[string]interface{}{  
		"status":  "success",  
		"message": "Logout successful, token blacklisted",  
	})  
  
	log.Printf("User logged out successfully: token=%s", tokenString)  
}  







