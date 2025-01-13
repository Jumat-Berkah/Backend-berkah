package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

// CreateFeedback allows a user to submit feedback for a mosque
func CreateFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract JWT from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}
	tokenString := authHeader[7:]

	claims := &model.Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JwtKey), nil
	})
	if err != nil {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	// Parse feedback data
	var feedback model.Feedback
	if err := json.NewDecoder(r.Body).Decode(&feedback); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if feedback.LocationID == 0 || feedback.Comment == "" {
		http.Error(w, "MosqueID and Comment are required fields", http.StatusBadRequest)
		return
	}

	// Assign the user ID from the claims to the feedback
	feedback.UserID = claims.UserID

	// Save feedback to the database
	if err := config.DB.Create(&feedback).Error; err != nil {
		http.Error(w, "Failed to submit feedback", http.StatusInternalServerError)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Feedback submitted successfully",
		"feedback": feedback,
	})
}

// GetFeedback retrieves feedback for a specific mosque
func GetFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract mosque ID from query params
	mosqueID := r.URL.Query().Get("mosque_id")
	if mosqueID == "" {
		http.Error(w, "MosqueID is required", http.StatusBadRequest)
		return
	}

	// Fetch feedback from the database
	var feedbacks []model.Feedback
	if err := config.DB.Where("mosque_id = ?", mosqueID).Find(&feedbacks).Error; err != nil {
		http.Error(w, "Failed to fetch feedback", http.StatusInternalServerError)
		return
	}

	// Respond with feedback data
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Feedback retrieved successfully",
		"feedback": feedbacks,
	})
}

// DeleteFeedback allows a user to delete their feedback
func DeleteFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract JWT from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}
	tokenString := authHeader[7:]

	claims := &model.Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JwtKey), nil
	})
	if err != nil {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	// Decode the request body to get feedback ID
	var input struct {
		FeedbackID uint `json:"feedback_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate the input
	if input.FeedbackID == 0 {
		http.Error(w, "FeedbackID is required", http.StatusBadRequest)
		return
	}

	// Check if the feedback exists and belongs to the user
	var feedback model.Feedback
	if err := config.DB.Where("id = ? AND user_id = ?", input.FeedbackID, claims.UserID).First(&feedback).Error; err != nil {
		http.Error(w, "Feedback not found or unauthorized access", http.StatusNotFound)
		return
	}

	// Delete the feedback
	if err := config.DB.Delete(&feedback).Error; err != nil {
		http.Error(w, "Failed to delete feedback", http.StatusInternalServerError)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Feedback deleted successfully",
		"id":      input.FeedbackID,
	})
}
