package model

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Location model
type Location struct {  
	ID          uint      `gorm:"primaryKey" json:"id"`  
	Name        string    `gorm:"type:varchar(100);not null" json:"name"`  
	Address     string    `gorm:"type:text;not null" json:"address"`
	EmbedLink   string    `gorm:"type:text" json:"embed_link"`  
	Description string    `gorm:"type:text" json:"description"`  
	CreatedAt   time.Time `gorm:"autoCreateTime"`      // Waktu dibuat  
}  
  
// ActiveToken model  
type ActiveToken struct {  
	ID        uint      `gorm:"primaryKey"`               // ID unik untuk setiap token  
	UserID    uint      `gorm:"not null"`                // ID user yang memiliki token ini (relasi ke tabel User)  
	Token     string    `gorm:"unique;not null"`         // Token JWT  
	ExpiresAt time.Time `gorm:"not null"`                // Waktu kedaluwarsa token  
	CreatedAt time.Time `gorm:"autoCreateTime"`          // Waktu token dibuat  
}  
  
// BlacklistToken model  
type BlacklistToken struct {  
	ID        uint      `gorm:"primaryKey"`  
	Token     string    `gorm:"unique;not null"`  
	ExpiresAt time.Time `gorm:"not null"`  
	CreatedAt time.Time `gorm:"autoCreateTime"` // Waktu dibuat  
}  
  
// Token model  
type Token struct {  
	ID        uint      `gorm:"primaryKey"`  
	UserID    uint      `gorm:"not null"` // Relasi ke User  
	User      User      `gorm:"foreignKey:UserID"`  
	Token     string    `gorm:"unique;not null"`  
	Role      string    `gorm:"not null"`  
	CreatedAt time.Time `gorm:"autoCreateTime"` // Waktu dibuat  
	ExpiresAt time.Time `gorm:"not null"`       // Token Expiry Time  
}  

type Claims struct {  
	UserID    uint      `json:"user_id"`    // ID pengguna  
	Role      string    `json:"role"`       // Nama role pengguna  
	ExpiresAt time.Time  `json:"expires_at"` // Waktu kedaluwarsa token  
	jwt.RegisteredClaims // Menyimpan klaim terdaftar seperti Issuer, Subject, Audience, dan ExpiresAt  
} 

// RequestData model untuk registrasi  
type RequestData struct {  
	Email            string `json:"email"`  
	Username         string `json:"username"`  
	Password         string `json:"password"`  
	ConfirmPassword  string `json:"confirm_password"`  
}  
  
// LoginInput model untuk login  
type LoginInput struct {  
	Email    string `json:"email"`  
	Password string `json:"password"`  
}  
  
type ContextKey string

const (
    UserIDKey ContextKey = "userID"
    RoleKey   ContextKey = "role"
)