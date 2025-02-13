package model

import (
	"time"

	"gorm.io/gorm"
)

// Role model
type Role struct {  
	ID        uint      `gorm:"primaryKey"`  
	Name      string    `gorm:"unique;not null"`  
	Users     []User    `gorm:"foreignKey:RoleID"` // Relasi ke tabel users  
	CreatedAt time.Time `gorm:"autoCreateTime"`     // Waktu dibuat  
}  
  
type GoogleUser struct {
    ID        uint       `gorm:"primaryKey"`
    GoogleID  string     `gorm:"uniqueIndex;not null"` // ID unik dari Google
    Email     string     `gorm:"uniqueIndex;not null"`
    Name      string
    Picture   string
    CreatedAt time.Time
    LastLogin time.Time
    RoleID    int       `gorm:"default:1"` // Role ID default (user biasa)
    IsActive  bool      `gorm:"default:true"`
    Role      Role      `gorm:"foreignKey:RoleID"`
}
// User model  
type User struct {
    gorm.Model
    Email            string    `gorm:"unique;not null"`
    Username         string    `gorm:"unique;not null"`
    Password         string    `gorm:"not null"`
    FullName         string    `json:"full_name"`
    PhoneNumber      string    `json:"phone_number"`
    Address          string    `json:"address"`
    ProfilePicture   string    `json:"profile_picture"`
    PreferredMasjid  string    `json:"preferred_masjid"`
    DonationHistory  []Donation `gorm:"foreignKey:UserID"`
    Bio              string    `json:"bio"`
    JoinDate         time.Time `gorm:"autoCreateTime"`
    RoleID           uint      `gorm:"not null"`
    Role             Role      `gorm:"foreignKey:RoleID"`
    ResetToken       string    `json:"reset_token"`
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