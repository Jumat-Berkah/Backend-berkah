package helper

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Fungsi untuk hash password
func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(bytes), nil
}


// Middleware gabungan untuk validasi token dan otorisasi role
func AuthMiddleware(next http.Handler, allowedRoleIDs ...uint) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenString, err := GetTokenFromHeader(r)
        if err != nil {
            log.Printf("Token error: %v", err)
            http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
            return
        }

        if IsTokenBlacklisted(tokenString) {
            log.Printf("Token is blacklisted: %v", tokenString)
            http.Error(w, "Unauthorized: Token has been blacklisted", http.StatusUnauthorized)
            return
        }

        claims := &model.Claims{}
        if err := ParseAndValidateToken(tokenString, claims); err != nil {
            log.Printf("Token validation error: %v", err)
            http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
            return
        }

        var user model.User
        if err := config.DB.Preload("Role").First(&user, claims.UserID).Error; err != nil {
            log.Printf("User not found: %v", err)
            http.Error(w, "Unauthorized: User not found", http.StatusUnauthorized)
            return
        }

        // Otorisasi role (opsional)
        if allowedRoleIDs != nil { // Jika allowedRoleIDs diberikan
            roleAllowed := false
            for _, allowedRoleID := range allowedRoleIDs {
                if user.Role.ID == allowedRoleID {
                    roleAllowed = true
                    break
                }
            }

            if !roleAllowed {
                log.Printf("Access denied: insufficient permissions for role ID '%d'", user.Role.ID)
                http.Error(w, "Access denied: insufficient permissions", http.StatusForbidden)
                return
            }
        }

        ctx := context.WithValue(r.Context(), config.UserIDKey, claims.UserID)
        ctx = context.WithValue(ctx, config.RoleKey, user.Role.Name)

		// Perbarui token (opsional, jika Anda ingin memperbarui token setiap request)
		_, err = UpdateToken(config.DB, user.ID)
		if err != nil {
			log.Printf("Failed to update token: %v", err)
			http.Error(w, "Failed to update token", http.StatusInternalServerError)
			return
		}

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Fungsi untuk blacklist token
func BlacklistToken(w http.ResponseWriter, r *http.Request) {
	tokenString, err := GetTokenFromHeader(r)
	if err != nil {
		log.Printf("Token error: %v", err)
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Verifikasi token JWT
	claims := &model.Claims{}
	if err := ParseAndValidateToken(tokenString, claims); err != nil {
		log.Printf("Token validation error: %v", err)
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Simpan token ke dalam database sebagai blacklist
	blacklistToken := model.BlacklistToken{
		Token:     tokenString,
		ExpiresAt: claims.ExpiresAt,
		CreatedAt: time.Now(),
	}

	if err := config.DB.Create(&blacklistToken).Error; err != nil {
		log.Printf("Failed to insert token into blacklist: %v", err)
		http.Error(w, "Failed to blacklist token", http.StatusInternalServerError)
		return
	}

	// Kirim respons logout berhasil
	WriteResponse(w, http.StatusOK, map[string]string{
		"message": "Logout successful, token has been blacklisted",
	})
}

// ValidateUser checks the user's email and password
func ValidateUser(email, password string) (model.User, error) {
	var user model.User

	// Fetch user from the database based on email
	if err := config.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return model.User{}, errors.New("user not found")
	}

	// Compare the provided password with the stored hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return model.User{}, errors.New("invalid password")
	}

	return user, nil
}

// Helper: Ambil token dari header Authorization
func GetTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header is missing")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("authorization header format must be Bearer {token}")
	}
	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// Helper: Verifikasi dan validasi token JWT
func ParseAndValidateToken(tokenString string, claims *model.Claims) error {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JwtKey), nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return errors.New("token is invalid")
	}
	return nil
}

// Helper: Periksa apakah token ada di blacklist
func IsTokenBlacklisted(tokenString string) bool {
	var blacklistToken model.BlacklistToken
	if err := config.DB.Where("token = ?", tokenString).First(&blacklistToken).Error; err == nil {
		return true
	}
	return false
}

// Memindahkan token kedaluwarsa ke tabel blacklist
func MoveExpiredTokensToBlacklist() {
	var expiredTokens []model.ActiveToken
	if err := config.DB.Where("expires_at < ?", time.Now()).Find(&expiredTokens).Error; err != nil {
		log.Printf("Failed to find expired tokens: %v", err)
		return
	}

	// Pindahkan token ke blacklist_tokens
	for _, token := range expiredTokens {
		blacklistToken := model.BlacklistToken{
			Token:     token.Token,
			ExpiresAt: token.ExpiresAt,
			CreatedAt: time.Now(),
		}
		if err := config.DB.Create(&blacklistToken).Error; err != nil {
			log.Printf("Failed to move token to blacklist: %v", err)
			continue
		}

		// Hapus token dari active_tokens
		if err := config.DB.Delete(&token).Error; err != nil {
			log.Printf("Failed to delete token from active_tokens: %v", err)
		}
	}

	log.Printf("Moved %d expired tokens to blacklist.", len(expiredTokens))
}

// Penjadwalan pembersihan token
func ScheduleTokenCleanup() error {
	scheduler := gocron.NewScheduler(time.UTC)

	// Jadwalkan cleanup setiap jam
	_, err := scheduler.Every(1).Hour().Do(func() {
		log.Println("Running token cleanup...")
		MoveExpiredTokensToBlacklist()
	})
	if err != nil {
		return err
	}

	// Mulai scheduler
	scheduler.StartAsync()
	return nil
}

// GenerateToken generates a JWT token
func GenerateToken(userID uint, role string) (string, error) {
	expirationTime := time.Now().Add(2 * time.Hour) // Set expiration time to 2 hours
	claims := model.Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(config.JwtKey) // Use your secret key from config
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// StoreToken stores the token in the tokens table
func StoreToken(tokenString string, userID uint, role string, expiresAt time.Time) error {
	token := model.Token{
		Token:     tokenString,
		UserID:    userID,
		Role:      role,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	return config.DB.Create(&token).Error
}

// StoreActiveToken stores the token in the active_tokens table
func StoreActiveToken(tokenString string, userID uint, expiresAt time.Time) error {
	activeToken := model.ActiveToken{
		Token:     tokenString,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	return config.DB.Create(&activeToken).Error
}

// Fungsi untuk memperbarui token (misalnya, di middleware atau handler)
func UpdateToken(db *gorm.DB, userID uint) (string, error) {
	// Assuming you have the role available, replace "userRole" with the actual role variable
	token, err := GenerateToken(userID, "userRole")
    if err != nil {
        return "", err
    }

    expiry := time.Now().Add(time.Hour) // Token berlaku 1 jam

    err = db.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
        "token": token,
        "token_expiry": expiry,
    }).Error

    if err != nil {
        return "", err
    }

    return token, nil
}