package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

func GetDataLocation(w http.ResponseWriter, r *http.Request) {
    log.Println("GetDataLocation called")

    // Pastikan hanya menerima metode GET
    if r.Method != http.MethodGet {
        log.Println("Invalid method:", r.Method)
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Ambil semua data dari tabel `locations`
    var locations []model.Location
    if err := config.DB.Find(&locations).Error; err != nil {
        log.Printf("Database error: %v", err)
        http.Error(w, "Failed to fetch locations", http.StatusInternalServerError)
        return
    }

    // Jika tidak ada data yang ditemukan
    if len(locations) == 0 {
        log.Println("No locations found")
        http.Error(w, "No locations found", http.StatusNotFound)
        return
    }

    // Kirim hasil dalam format JSON
    log.Printf("Locations retrieved successfully: %d records", len(locations))
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":  "success",
        "message": "Locations retrieved successfully",
        "data":    locations,
    })
}


func CreateDataLocation(w http.ResponseWriter, r *http.Request) {
    log.Println("CreateDataLocation called")

    // Pastikan hanya menerima metode POST
    if r.Method != http.MethodPost {
        log.Println("Invalid method:", r.Method)
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Periksa apakah pengguna memiliki role "admin"
    role := r.Context().Value("role")
    if role == nil || role != "admin" {
        log.Println("Access denied: User is not admin")
        http.Error(w, "Access denied: only admins can create locations", http.StatusForbidden)
        return
    }

    // Parse body JSON request
    var newLocation model.Location
    if err := json.NewDecoder(r.Body).Decode(&newLocation); err != nil {
        log.Printf("Invalid request payload: %v", err)
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Validasi input
    if newLocation.Name == "" || newLocation.Address == "" {
        log.Println("Validation error: Name or Address is empty")
        http.Error(w, "Name and Address are required fields", http.StatusBadRequest)
        return
    }

    // Simpan lokasi ke database
    if err := config.DB.Create(&newLocation).Error; err != nil {
        log.Printf("Database error: %v", err)
        http.Error(w, "Failed to create location", http.StatusInternalServerError)
        return
    }

    // Kirim respons sukses
    log.Printf("Location created successfully: %+v", newLocation)
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":  "success",
        "message": "Location created successfully",
        "data":    newLocation,
    })
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
