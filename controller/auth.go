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

    state := config.GenerateStateString()

    http.SetCookie(w, &http.Cookie{
        Name:     "oauthstate",
        Value:    state,
        Expires:  time.Now().Add(10 * time.Minute),
        HttpOnly: true,
        Secure:   true, // Ganti true jika menggunakan HTTPS
        SameSite: http.SameSiteNoneMode, // Gunakan dengan hati-hati, atau Strict jika bukan HTTPS
        Path:     "/",
        Domain:   "jumatberkah.vercel.app", // Ganti dengan domain Anda
    })

    url := config.GoogleOauthConfig.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    oauthCookie, err := r.Cookie("oauthstate")
    if err != nil {
        fmt.Println("Error getting oauthstate cookie:", err) // Tambahkan log
        http.Error(w, "State cookie not found", http.StatusBadRequest)
        return
    }

    fmt.Println("oauthstate cookie value:", oauthCookie.Value)

    if r.FormValue("state") != oauthCookie.Value {
        http.Error(w, "Invalid oauth state", http.StatusBadRequest)
        return
    }

    token, err := config.GoogleOauthConfig.Exchange(r.Context(), r.FormValue("code"))
    if err != nil {
        http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    client := config.GoogleOauthConfig.Client(r.Context(), token)
    userInfo, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
    if err != nil {
        http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer userInfo.Body.Close()

    var googleUser struct {
        Email    string `json:"email"`
        Name     string `json:"name"`
        Picture  string `json:"picture"`
        GoogleID string `json:"sub"`
    }

    if err := json.NewDecoder(userInfo.Body).Decode(&googleUser); err != nil {
        http.Error(w, "Failed to decode user info: "+err.Error(), http.StatusInternalServerError)
        return
    }

    var user model.GoogleUser
    result := config.DB.Where("google_id = ?", googleUser.GoogleID).First(&user)

    if result.Error != nil {
        user = model.GoogleUser{
            GoogleID: googleUser.GoogleID,
            Email:    googleUser.Email,
            Name:     googleUser.Name,
            Picture:  googleUser.Picture,
            RoleID:   1,
            IsActive: true,
        }

        if err := config.DB.Create(&user).Error; err != nil {
            http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
            return
        }
    } else {
        if err := config.DB.Model(&user).Update("last_login", time.Now()).Error; err != nil {
            http.Error(w, "Failed to update last login: "+err.Error(), http.StatusInternalServerError)
            return
        }
    }

    jwtToken, err := helper.GenerateToken(user.ID, user.Role.Name)
    if err != nil {
        http.Error(w, "Failed to generate token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    redirectURL := fmt.Sprintf("https://backend-berkah.onrender.com/?token=%s", jwtToken) // Redirect ke domain yang sama
    http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}














