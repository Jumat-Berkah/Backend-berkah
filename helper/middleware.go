package helper

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/golang-jwt/jwt/v4"
)

// Middleware untuk memvalidasi role pengguna
// Middleware untuk memvalidasi role pengguna
func RoleMiddleware(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ambil token dari header Authorization
			tokenString, err := getTokenFromHeader(r)
			if err != nil {
				log.Printf("Token error: %v", err)
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Verifikasi token JWT
			claims := &model.Claims{}
			if err := parseAndValidateToken(tokenString, claims); err != nil {
				log.Printf("Token validation error: %v", err)
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Validasi apakah role pengguna termasuk dalam daftar allowedRoles
			if !isRoleAllowed(claims.Role, allowedRoles) {
				log.Printf("Access denied: insufficient permissions for role '%s'", claims.Role)
				http.Error(w, "Access denied: insufficient permissions", http.StatusForbidden)
				return
			}

			// Masukkan userID dan role ke context request
			ctx := context.WithValue(r.Context(), model.UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, model.RoleKey, claims.Role)

			// Lanjutkan ke handler berikutnya
			log.Printf("Access granted: userID=%d, role=%s", claims.UserID, claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}



// Fungsi untuk blacklist token
func BlacklistToken(w http.ResponseWriter, r *http.Request) {
	tokenString, err := getTokenFromHeader(r)
	if err != nil {
		log.Printf("Token error: %v", err)
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Verifikasi token JWT
	claims := &model.Claims{}
	if err := parseAndValidateToken(tokenString, claims); err != nil {
		log.Printf("Token validation error: %v", err)
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Simpan token ke dalam database sebagai blacklist
	blacklistToken := model.BlacklistToken{
		Token:     tokenString,
		ExpiresAt: claims.ExpiresAt.Time,
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

// Middleware untuk memvalidasi token
func ValidateTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ambil token dari header
		tokenString, err := getTokenFromHeader(r)
		if err != nil {
			log.Printf("Token error: %v", err)
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Periksa apakah token ada di blacklist
		if isTokenBlacklisted(tokenString) {
			log.Printf("Token is blacklisted: %v", tokenString)
			http.Error(w, "Unauthorized: Token has been blacklisted", http.StatusUnauthorized)
			return
		}

		// Verifikasi token JWT
		claims := &model.Claims{}
		if err := parseAndValidateToken(tokenString, claims); err != nil {
			log.Printf("Token validation error: %v", err)
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Masukkan userID dan role ke context request
		ctx := context.WithValue(r.Context(), model.UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, model.RoleKey, claims.Role)

		log.Printf("Token validated successfully: userID=%d, role=%s", claims.UserID, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper: Ambil token dari header Authorization
func getTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", http.ErrNoCookie
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", http.ErrNoCookie
	}
	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// Helper: Verifikasi dan validasi token JWT
func parseAndValidateToken(tokenString string, claims *model.Claims) error {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JwtKey), nil
	})
	if err != nil || !token.Valid {
		return http.ErrNoCookie
	}
	return nil
}

// Helper: Periksa apakah token ada di blacklist
func isTokenBlacklisted(tokenString string) bool {
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

func isRoleAllowed(userRole string, allowedRoles []string) bool {
	for _, role := range allowedRoles {
		if userRole == role {
			return true
		}
	}
	return false
}
