package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/helper"
	"Backend-berkah/model"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
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
    url := config.GoogleOauthConfig.AuthCodeURL(config.OauthStateString, oauth2.AccessTypeOffline)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
    state := r.FormValue("state")
    if state != config.OauthStateString {
        fmt.Fprintf(w, "invalid oauth state")
        return
    }

    code := r.FormValue("code")
    token, err := config.GoogleOauthConfig.Exchange(oauth2.NoContext, code)
    if err != nil {
        fmt.Fprintf(w, "code exchange wrong: %s", err.Error())
        return
    }

    response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
    if err != nil {
        fmt.Fprintf(w, "failed getting user info: %s", err.Error())
        return
    }
    defer response.Body.Close()

    var userInfo map[string]interface{}
    err = json.NewDecoder(response.Body).Decode(&userInfo)
    if err != nil {
        fmt.Fprintf(w, "failed decoding user info: %s", err.Error())
        return
    }

    fmt.Fprintf(w, "Hello, %s!", userInfo["name"])
}














