package helper

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func Authenticate(next http.Handler) http.Handler {
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

		// Masukkan userID dan role ke context request
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "role", claims.Role)

		// Lanjutkan ke handler berikutnya dengan context yang diperbarui
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
