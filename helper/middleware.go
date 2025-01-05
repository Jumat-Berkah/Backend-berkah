package helper

import (
	"Backend-berkah/config"
	"Backend-berkah/model"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

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
                return []byte(config.JwtKey), nil
            })

            if err != nil || !token.Valid {
                http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
                return
            }

            // Validasi apakah role pengguna termasuk dalam daftar allowedRoles
            for _, role := range allowedRoles {
                if claims.Role == role {
                    // Role valid, masukkan userID dan role ke context request
                    ctx := context.WithValue(r.Context(), model.UserIDKey, claims.UserID)
                    ctx = context.WithValue(ctx, model.RoleKey, claims.Role)

                    // Lanjutkan ke handler berikutnya
                    next.ServeHTTP(w, r.WithContext(ctx))
                    return
                }
            }

            // Role tidak diizinkan
            http.Error(w, "Access denied: insufficient permissions", http.StatusForbidden)
        })
    }
}


func BlacklistToken(w http.ResponseWriter, r *http.Request) {
    // Ambil token dari header Authorization
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
        return
    }

    // Hapus prefix "Bearer "
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")

    // Periksa apakah token valid
    claims := &model.Claims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return []byte(config.JwtKey), nil
    })

    if err != nil || !token.Valid {
        http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
        return
    }

    // Simpan token ke dalam database sebagai blacklist
    blacklistToken := model.BlacklistToken{
        Token:     tokenString,
        ExpiresAt: claims.ExpiresAt.Time,
    }

    if err := config.DB.Create(&blacklistToken).Error; err != nil {
        http.Error(w, "Failed to blacklist token", http.StatusInternalServerError)
        return
    }

    // Kirim respons logout berhasil
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Logout successful, token has been blacklisted",
    })
}

func ValidateTokenMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Ambil token dari header Authorization
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
            return
        }

        // Hapus prefix "Bearer "
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")

        // Periksa apakah token ada di blacklist
        var blacklistToken model.BlacklistToken
        if err := config.DB.Where("token = ?", tokenString).First(&blacklistToken).Error; err == nil {
            http.Error(w, "Token has been blacklisted", http.StatusUnauthorized)
            return
        }

        // Validasi token JWT
        claims := &model.Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(config.JwtKey), nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
            return
        }

        // Masukkan userID dan role ke context request
        ctx := context.WithValue(r.Context(), model.UserIDKey, claims.UserID)
        ctx = context.WithValue(ctx, model.RoleKey, claims.Role)

        // Lanjutkan ke handler berikutnya dengan context yang diperbarui
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

