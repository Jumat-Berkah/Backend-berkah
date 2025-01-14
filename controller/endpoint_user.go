package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

// GetDataFeedback retrieves all feedback
func GetDataFeedback(w http.ResponseWriter, r *http.Request) {  
	log.Println("GetDataFeedback called")  
  
	// Check HTTP method  
	if r.Method != http.MethodGet {  
		log.Println("Invalid method:", r.Method)  
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)  
		return  
	}  
  
	var token string  
  
	// Check Authorization header  
	authHeader := r.Header.Get("Authorization")  
	if authHeader != "" {  
		log.Println("Authorization header found:", authHeader)  
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {  
			token = authHeader[7:]  
		} else {  
			log.Println("Invalid Authorization header format")  
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)  
			return  
		}  
	} else {  
		// Check Cookie for Authorization  
		cookie, err := r.Cookie("Authorization")  
		if err != nil {  
			if err == http.ErrNoCookie {  
				log.Println("Authorization token not provided in header or cookie")  
				http.Error(w, "Unauthorized: Token not provided", http.StatusUnauthorized)  
				return  
			}  
			log.Printf("Failed to read Authorization cookie: %v", err)  
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)  
			return  
		}  
		log.Println("Authorization cookie found:", cookie.Value)  
		token = cookie.Value  
	}  
  
	// Log token found  
	log.Println("Token found:", token)  
  
	// Check if token is blacklisted  
	var blacklistedToken model.BlacklistToken  
	if err := config.DB.Where("token = ?", token).First(&blacklistedToken).Error; err == nil {  
		log.Println("Token is blacklisted or expired:", token)  
		http.Error(w, "Unauthorized: Token is blacklisted or expired", http.StatusUnauthorized)  
		return  
	} else if err != nil && err != gorm.ErrRecordNotFound {  
		log.Printf("Database error while checking token: %v", err)  
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)  
		return  
	}  
  
	// Retrieve all feedback from the database  
	var feedbacks []model.Feedback  
	if err := config.DB.Find(&feedbacks).Error; err != nil {  
		log.Printf("Database error while fetching feedback: %v", err)  
		http.Error(w, "Failed to fetch feedback", http.StatusInternalServerError)  
		return  
	}  
  
	// If no feedback found  
	if len(feedbacks) == 0 {  
		log.Println("No feedback found in the database")  
		w.Header().Set("Content-Type", "application/json")  
		w.WriteHeader(http.StatusOK)  
		json.NewEncoder(w).Encode(map[string]interface{}{  
			"status":  "success",  
			"message": "No feedback found",  
			"data":    []model.Feedback{},  
		})  
		return  
	}  
  
	// Send results in JSON format  
	log.Printf("Feedback retrieved successfully: %d records", len(feedbacks))  
	w.Header().Set("Content-Type", "application/json")  
	w.WriteHeader(http.StatusOK)  
	json.NewEncoder(w).Encode(map[string]interface{}{  
		"status":  "success",  
		"message": "Feedback retrieved successfully",  
		"data":    feedbacks,  
	})  
}  
  
// CreateFeedback creates a new feedback entry  
func CreateFeedback(w http.ResponseWriter, r *http.Request) {  
    log.Println("CreateFeedback called")  
  
    // Ensure only POST method is accepted  
    if r.Method != http.MethodPost {  
        log.Println("Invalid method:", r.Method)  
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)  
        return  
    }  
  
    var token string  
  
    // Get token from Authorization header  
    authHeader := r.Header.Get("Authorization")  
    if authHeader != "" {  
        log.Println("Authorization header found:", authHeader)  
        if len(authHeader) > 7 && authHeader[:7] == "Bearer " {  
            token = authHeader[7:]  
        } else {  
            log.Println("Invalid Authorization header format")  
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)  
            return  
        }  
    } else {  
        // If token is not in Authorization header, try to get from Cookie  
        cookie, err := r.Cookie("Authorization")  
        if err != nil {  
            if err == http.ErrNoCookie {  
                log.Println("Authorization token not provided in header or cookie")  
                http.Error(w, "Unauthorized: Token not provided", http.StatusUnauthorized)  
                return  
            }  
            log.Printf("Failed to read Authorization cookie: %v", err)  
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)  
            return  
        }  
        log.Println("Authorization cookie found:", cookie.Value)  
        token = cookie.Value  
    }  
  
    // Validate token with JWT  
    claims := &model.Claims{}  
    _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {  
        return []byte(config.JwtKey), nil  
    })  
    if err != nil {  
        log.Printf("Failed to parse token: %v", err)  
        http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)  
        return  
    }  
  
    log.Println("Token claims:", claims)  
  
    // Parse body JSON request  
    var newFeedback model.Inputuserupdate
      
    if err := json.NewDecoder(r.Body).Decode(&newFeedback); err != nil {  
        log.Printf("Invalid request payload: %v", err)  
        http.Error(w, "Invalid request payload", http.StatusBadRequest)  
        return  
    }  
  
    // Validate input  
    if newFeedback.Name == "" || newFeedback.Address == "" || newFeedback.Rating < 1 || newFeedback.Rating > 5 {  
        log.Println("Validation error: Name, Address, and Rating must be valid")  
        http.Error(w, "Name, Address, and Rating must be valid", http.StatusBadRequest)  
        return  
    }  
  
    // Create feedback instance with additional fields  
    feedback := model.Feedback{  
        UserID:      claims.UserID, // Assuming claims.UserID contains the ID of the authenticated user  
        Name:        newFeedback.Name,  
        Address:     newFeedback.Address,  
        Description: newFeedback.Description,  
        Rating:      newFeedback.Rating,  
        Comment:     newFeedback.Comment,  
        CreatedAt:   time.Now(), // Automatically set created_at  
        UpdatedAt:   time.Now(), // Automatically set updated_at  
    }  
  
    // Save feedback to database  
    if err := config.DB.Create(&feedback).Error; err != nil {  
        log.Printf("Database error: %v", err)  
        http.Error(w, "Failed to create feedback", http.StatusInternalServerError)  
        return  
    }  
  
    // Send success response with ID  
    log.Printf("Feedback created successfully: %+v", feedback)  
    w.Header().Set("Content-Type", "application/json")  
    w.WriteHeader(http.StatusCreated)  
    json.NewEncoder(w).Encode(map[string]interface{}{  
        "name":        feedback.Name,  
        "address":     feedback.Address,  
        "description": feedback.Description,  
        "rating":      feedback.Rating,  
        "comment":     feedback.Comment,  
    })  
}  
  
// UpdateFeedback updates an existing feedback entry  
func UpdateFeedback(w http.ResponseWriter, r *http.Request) {  
    log.Println("UpdateFeedback called")  
  
    // Ensure only PUT method is accepted  
    if r.Method != http.MethodPut {  
        log.Println("Invalid method:", r.Method)  
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)  
        return  
    }  
  
    var token string  
  
    // Get token from Authorization header  
    authHeader := r.Header.Get("Authorization")  
    if authHeader != "" {  
        log.Println("Authorization header found:", authHeader)  
        if len(authHeader) > 7 && authHeader[:7] == "Bearer " {  
            token = authHeader[7:]  
        } else {  
            log.Println("Invalid Authorization header format")  
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)  
            return  
        }  
    } else {  
        // If token is not in Authorization header, try to get from Cookie  
        cookie, err := r.Cookie("Authorization")  
        if err != nil {  
            if err == http.ErrNoCookie {  
                log.Println("Authorization token not provided in header or cookie")  
                http.Error(w, "Unauthorized: Token not provided", http.StatusUnauthorized)  
                return  
            }  
            log.Printf("Failed to read Authorization cookie: %v", err)  
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)  
            return  
        }  
        log.Println("Authorization cookie found:", cookie.Value)  
        token = cookie.Value  
    }  
  
    // Validate token with JWT  
    claims := &model.Claims{}  
    _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {  
        return []byte(config.JwtKey), nil  
    })  
    if err != nil {  
        log.Printf("Failed to parse token: %v", err)  
        http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)  
        return  
    }  
  
    log.Println("Token claims:", claims)  
  
    // Get ID from query parameter  
    feedbackID := r.URL.Query().Get("id")  
    if feedbackID == "" {  
        log.Println("Validation error: ID is required")  
        http.Error(w, "ID is required", http.StatusBadRequest)  
        return  
    }  
  
    // Decode JSON request body to get data to be updated  
    var input model.Inputuserupdate
      
    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {  
        log.Printf("Invalid request body: %v", err)  
        http.Error(w, "Invalid input", http.StatusBadRequest)  
        return  
    }  
  
    // Validate input  
    if input.Name == "" || input.Address == "" || input.Rating < 1 || input.Rating > 5 {  
        log.Println("Validation error: Name, Address, and Rating must be valid")  
        http.Error(w, "Name, Address, and Rating must be valid", http.StatusBadRequest)  
        return  
    }  
  
    // Find feedback by ID  
    var existingFeedback model.Feedback  
    if err := config.DB.First(&existingFeedback, feedbackID).Error; err != nil {  
        log.Printf("Data not found for ID: %s", feedbackID)  
        http.Error(w, "Data not found", http.StatusNotFound)  
        return  
    }  
  
    // Update fields  
    existingFeedback.Name = input.Name  
    existingFeedback.Address = input.Address  
    if input.Description != nil {  
        existingFeedback.Description = input.Description  
    } else {  
        existingFeedback.Description = nil  
    }  
    existingFeedback.Rating = input.Rating  
    existingFeedback.Comment = input.Comment  
    existingFeedback.UpdatedAt = time.Now() // Update timestamp  
  
    // Save changes to database  
    if err := config.DB.Save(&existingFeedback).Error; err != nil {  
        log.Printf("Failed to update data for ID: %s, error: %v", feedbackID, err)  
        http.Error(w, "Failed to update data", http.StatusInternalServerError)  
        return  
    }  
  
    // Send success response  
    log.Printf("Feedback updated successfully for ID: %s", feedbackID)  
    w.Header().Set("Content-Type", "application/json")  
    w.WriteHeader(http.StatusOK)  
    json.NewEncoder(w).Encode(map[string]interface{}{  
        "name":        existingFeedback.Name,  
        "address":     existingFeedback.Address,  
        "description": existingFeedback.Description,  
        "rating":      existingFeedback.Rating,  
        "comment":     existingFeedback.Comment,  
    })  
}  
  
// DeleteFeedback deletes an existing feedback entry  
func DeleteFeedback(w http.ResponseWriter, r *http.Request) {  
    log.Println("DeleteFeedback called")  
  
    // Ensure only DELETE method is accepted  
    if r.Method != http.MethodDelete {  
        log.Println("Invalid method:", r.Method)  
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)  
        return  
    }  
  
    var token string  
  
    // Get token from Authorization header  
    authHeader := r.Header.Get("Authorization")  
    if authHeader != "" {  
        log.Println("Authorization header found:", authHeader)  
        if len(authHeader) > 7 && authHeader[:7] == "Bearer " {  
            token = authHeader[7:]  
        } else {  
            log.Println("Invalid Authorization header format")  
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)  
            return  
        }  
    } else {  
        // If token is not in Authorization header, try to get from Cookie  
        cookie, err := r.Cookie("Authorization")  
        if err != nil {  
            if err == http.ErrNoCookie {  
                log.Println("Authorization token not provided in header or cookie")  
                http.Error(w, "Unauthorized: Token not provided", http.StatusUnauthorized)  
                return  
            }  
            log.Printf("Failed to read Authorization cookie: %v", err)  
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)  
            return  
        }  
        log.Println("Authorization cookie found:", cookie.Value)  
        token = cookie.Value  
    }  
  
    // Validate token with JWT  
    claims := &model.Claims{}  
    _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {  
        return []byte(config.JwtKey), nil  
    })  
    if err != nil {  
        log.Printf("Failed to parse token: %v", err)  
        http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)  
        return  
    }  
  
    log.Println("Token claims:", claims)  
  
    // Get ID from query parameter  
    feedbackID := r.URL.Query().Get("id")  
    if feedbackID == "" {  
        log.Println("Validation error: ID is required")  
        http.Error(w, "ID is required", http.StatusBadRequest)  
        return  
    }  
  
    // Find feedback by ID  
    var feedback model.Feedback  
    if err := config.DB.First(&feedback, feedbackID).Error; err != nil {  
        log.Printf("Data not found for ID: %s", feedbackID)  
        http.Error(w, "Data not found", http.StatusNotFound)  
        return  
    }  
  
    // Delete feedback from database  
    if err := config.DB.Delete(&feedback).Error; err != nil {  
        log.Printf("Failed to delete data for ID: %s, error: %v", feedbackID, err)  
        http.Error(w, "Failed to delete data", http.StatusInternalServerError)  
        return  
    }  
  
    // Send success response  
    log.Printf("Feedback deleted successfully for ID: %s", feedbackID)  
    w.Header().Set("Content-Type", "application/json")  
    w.WriteHeader(http.StatusOK)  
    json.NewEncoder(w).Encode(map[string]interface{}{  
        "message": "Feedback deleted successfully",  
        "id":      feedbackID,  
    })  
}  
  
  
  
