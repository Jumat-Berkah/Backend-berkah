package helper

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &model.Claims{} // Gunakan model.Claims

		// Verifikasi token
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return config.JwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Simpan role ke context jika diperlukan
		r.Header.Set("Role", claims.Role)

		// Lanjutkan ke handler berikutnya
		next.ServeHTTP(w, r)
	})
}
