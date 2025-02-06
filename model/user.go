package model

import (
	"time"
)

// Role model
type Role struct {  
	ID        uint      `gorm:"primaryKey"`  
	Name      string    `gorm:"unique;not null"`  
	Users     []User    `gorm:"foreignKey:RoleID"` // Relasi ke tabel users  
	CreatedAt time.Time `gorm:"autoCreateTime"`     // Waktu dibuat  
}  
  
// User model  
type User struct {  
    ID              uint       `gorm:"primaryKey"`  
    Email           string     `gorm:"unique;not null"`  
    Username        string     `gorm:"unique;not null"`  
    Password        string     `gorm:"not null"`  
    FullName        string     `json:"full_name"`
    PhoneNumber     string     `json:"phone_number"`
    Address         string     `json:"address"`
    ProfilePicture  string     `json:"profile_picture"`
    // Informasi Reset Password
    ResetToken      string     `json:"reset_token"`
    ResetTokenExpiry *time.Time `json:"reset_token_expiry"`
    // Informasi Keagamaan
    PreferredMasjid string     `json:"preferred_masjid"` // Masjid yang sering dikunjungi
    DonationHistory []Donation  `gorm:"foreignKey:UserID"` // Riwayat donasi
    // Informasi Tambahan
    Bio             string     `json:"bio"`
    JoinDate        time.Time  `gorm:"autoCreateTime"`
    RoleID          uint       `gorm:"not null"`
    Role            Role       `gorm:"foreignKey:RoleID"`
}

type Donation struct {
    ID          uint      `gorm:"primaryKey"`
    UserID      uint      `json:"user_id"`
    Amount      float64   `json:"amount"`
    MasjidID    uint      `json:"masjid_id"`
    Description string    `json:"description"`
    Date        time.Time `gorm:"autoCreateTime"`
    Status      string    `json:"status"` // pending, completed, cancelled
}

type UpdatedProfile struct {
	UserID          uint    `json:"user_id"`
	Username        string  `json:"username"`
	Email          string  `json:"email"`
	FullName       string  `json:"full_name"`
	PhoneNumber    string  `json:"phone_number"`
	Address        string  `json:"address"`
	PreferredMasjid string `json:"preferred_masjid"`
	Bio            string  `json:"bio"`
	OldPassword    string  `json:"old_password,omitempty"`
	NewPassword    string  `json:"new_password,omitempty"`
}

// Tambahkan struct baru untuk request reset password
type ResetPasswordRequest struct {
    Email string `json:"email"`
}

// Tambahkan struct untuk update password
type UpdatePasswordRequest struct {
    Token       string `json:"token"`
    NewPassword string `json:"new_password"`
}