package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// Get Data
func GetData(w http.ResponseWriter, r *http.Request) {
	var users []model.User
	if err := config.DB.Find(&users).Error; err != nil {
		http.Error(w, "Failed to fetch data", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// Post Data
func PostData(w http.ResponseWriter, r *http.Request) {
	var user model.User

	// Decode JSON request body
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Simpan ke database
	if err := config.DB.Create(&user).Error; err != nil {
		http.Error(w, "Failed to save data", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Data created successfully"})
}

// Update Data
func UpdateData(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var user model.User
	// Cari data berdasarkan ID
	if err := config.DB.First(&user, id).Error; err != nil {
		http.Error(w, "Data not found", http.StatusNotFound)
		return
	}

	// Decode JSON request body
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Update data
	if err := config.DB.Save(&user).Error; err != nil {
		http.Error(w, "Failed to update data", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Data updated successfully"})
}

// Delete Data
func DeleteData(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	// Hapus data berdasarkan ID
	if err := config.DB.Delete(&model.User{}, id).Error; err != nil {
		http.Error(w, "Failed to delete data", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Data deleted successfully"})
}
