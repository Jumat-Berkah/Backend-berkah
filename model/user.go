package model

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Role struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string    `gorm:"unique;not null"`
	Users     []User    `gorm:"foreignKey:RoleID"` // Relasi ke tabel users
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type BlacklistToken struct {
    ID        uint      `gorm:"primaryKey"`
    Token     string    `gorm:"unique;not null"`
    ExpiresAt time.Time `gorm:"not null"`
    CreatedAt time.Time
}
type Token struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"not null"` // Relasi ke User
	User      User      `gorm:"foreignKey:UserID"`
	Token     string    `gorm:"unique;not null"`
	Role      string    `gorm:"not null"`
	CreatedAt time.Time
	ExpiresAt time.Time // Token Expiry Time
}
type User struct {
	ID        uint      `gorm:"primaryKey"`
	Email     string    `gorm:"unique;not null"`
	Username  string    `gorm:"unique;not null"`
	Password  string    `gorm:"not null"`
	RoleID    uint      `gorm:"not null"`           // Foreign key ke tabel roles
	Role      Role      `gorm:"foreignKey:RoleID"`  // Relasi ke Role
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type LoginInput struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Role      string `json:"role"`
}

type RequestData struct {
	Email           string `json:"email"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	Role            string `json:"role"`
}

type Claims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type ContextKey string

const (
	UserIDKey ContextKey = "userID"
	RoleKey   ContextKey = "role"
)