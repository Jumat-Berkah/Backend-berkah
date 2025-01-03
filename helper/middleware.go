package helper

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// Middleware untuk memeriksa akses berdasarkan role
func RoleMiddleware(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ambil token dari header Authorization
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
				return
			}

			// Hapus prefix "Bearer "
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// Buat klaim token
			claims := &model.Claims{}

			// Verifikasi token JWT
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(config.JwtKey), nil // Ambil kunci rahasia dari config
			})

			if err != nil || !token.Valid {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Validasi apakah role pengguna termasuk dalam daftar allowedRoles
			roleAllowed := false
			for _, role := range allowedRoles {
				if claims.Role == role {
					roleAllowed = true
					break
				}
			}

			if !roleAllowed {
				http.Error(w, "Access denied: insufficient permissions", http.StatusForbidden)
				return
			}

			// Masukkan userID dan role ke context request
			ctx := context.WithValue(r.Context(), model.UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, model.RoleKey, claims.Role)

			// Lanjutkan ke handler berikutnya dengan context yang diperbarui
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
