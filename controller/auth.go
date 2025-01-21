package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
	"Backend-berkah/model"
	"encoding/json"
	"log"
	"net/http"

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
  
	//validate input
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
    if err := config.DB.Where("email = ?", loginInput.Email).First(&user).Error; err != nil {  
        log.Printf("User not found: %v", err)  
        http.Error(w, "Invalid email or password", http.StatusUnauthorized)  
        return  
    }  
  
    // Verifikasi password  
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginInput.Password)); err != nil {  
        log.Printf("Invalid password: %v", err)  
        http.Error(w, "Invalid email or password", http.StatusUnauthorized)  
        return  
    }  
  
    token, err := helper.GenerateToken(user.ID, user.Role.Name)  
	if err != nil {  
    log.Printf("Failed to generate token for user ID: %d, error: %v", user.ID, err)  
    http.Error(w, "Failed to generate token", http.StatusInternalServerError)  
    return  
}  

  
    // Kirim respons sukses dengan token  
    w.Header().Set("Content-Type", "application/json")  
    w.WriteHeader(http.StatusOK)  
    json.NewEncoder(w).Encode(map[string]interface{}{  
        "message": "Login successful",  
        "token":   token,  
        "user": map[string]interface{}{  
            "id":    user.ID,  
            "email": user.Email,  
            "role":  user.RoleID,  
        },  
    })  
}  






