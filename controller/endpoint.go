package controller

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"encoding/json"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

func GetDataLocation(w http.ResponseWriter, r *http.Request) {
    log.Println("GetDataLocation called")

    // Periksa metode HTTP
    if r.Method != http.MethodGet {
        log.Println("Invalid method:", r.Method)
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var token string

    // Cek header Authorization
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
        // Cek header Cookie
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

    // Log token yang ditemukan
    log.Println("Token found:", token)

    // Periksa apakah token ada di blacklist
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

    // Ambil semua data dari tabel `locations`
    var locations []model.Location
    if err := config.DB.Find(&locations).Error; err != nil {
        log.Printf("Database error while fetching locations: %v", err)
        http.Error(w, "Failed to fetch locations", http.StatusInternalServerError)
        return
    }

    // Jika tidak ada data yang ditemukan
    if len(locations) == 0 {
        log.Println("No locations found in the database")
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "status":  "success",
            "message": "No locations found",
            "data":    []model.Location{},
        })
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

	var token string

	// Ambil token dari header Authorization
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
		// Jika token tidak ada di Authorization header, coba ambil dari Cookie
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

	// Validasi token dengan JWT
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

	// Periksa apakah pengguna memiliki role "admin"
	if claims.Role != "admin" {
		log.Println("Access denied: User is not admin. Role:", claims.Role)
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

	// Kirim respons sukses dengan ID
	log.Printf("Location created successfully: %+v", newLocation)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          newLocation.ID,
		"name":        newLocation.Name,
		"address":     newLocation.Address,
		"description": newLocation.Description,
	})
}


func UpdateDataLocation(w http.ResponseWriter, r *http.Request) {
	log.Println("UpdateDataLocation called")

	// Pastikan hanya menerima metode PUT
	if r.Method != http.MethodPut {
		log.Println("Invalid method:", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode JSON request body untuk mendapatkan data yang akan diperbarui
	var input model.Input
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("Invalid request body: %v", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Validasi input ID
	if input.ID == 0 {
		log.Println("Validation error: ID is required")
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	// Cari lokasi berdasarkan ID
	var existingLocation model.Location
	if err := config.DB.First(&existingLocation, input.ID).Error; err != nil {
		log.Printf("Data not found for ID: %d", input.ID)
		http.Error(w, "Data not found", http.StatusNotFound)
		return
	}

	// Update hanya kolom yang diisi dalam request body
	if input.Name != "" {
		existingLocation.Name = input.Name
	}
	if input.Address != "" {
		existingLocation.Address = input.Address
	}
	if input.Description != "" {
		existingLocation.Description = input.Description
	}

	// Simpan perubahan ke database
	if err := config.DB.Save(&existingLocation).Error; err != nil {
		log.Printf("Failed to update data for ID: %d, error: %v", existingLocation.ID, err)
		http.Error(w, "Failed to update data", http.StatusInternalServerError)
		return
	}

	// Kirim respons sukses
	log.Printf("Location updated successfully for ID: %d", existingLocation.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          existingLocation.ID,
		"name":        existingLocation.Name,
		"address":     existingLocation.Address,
		"description": existingLocation.Description,
	})
}

func DeleteDataLocation(w http.ResponseWriter, r *http.Request) {
	log.Println("DeleteData called")

	// Pastikan hanya menerima metode DELETE
	if r.Method != http.MethodDelete {
		log.Println("Invalid method:", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode JSON request body
	var input struct {
		ID uint `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("Invalid request payload: %v", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Validasi input ID
	if input.ID == 0 {
		log.Println("Validation error: ID is required")
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	// Cari lokasi berdasarkan ID
	var location model.Location
	if err := config.DB.First(&location, input.ID).Error; err != nil {
		log.Printf("Data not found for ID: %d", input.ID)
		http.Error(w, "Data not found", http.StatusNotFound)
		return
	}

	// Hapus lokasi dari database
	if err := config.DB.Delete(&location).Error; err != nil {
		log.Printf("Failed to delete data for ID: %d, error: %v", input.ID, err)
		http.Error(w, "Failed to delete data", http.StatusInternalServerError)
		return
	}

	// Kirim respons sukses
	log.Printf("Location deleted successfully for ID: %d", input.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Data deleted successfully",
		"id":      input.ID,
	})
}


