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
	ID        uint      `gorm:"primaryKey"`  
	Email     string    `gorm:"unique;not null"`  
	Username  string    `gorm:"unique;not null"`  
	Password  string    `gorm:"not null"`  
	RoleID    uint      `gorm:"not null"`           // Foreign key ke tabel roles  
	Role      Role      `gorm:"foreignKey:RoleID"`  // Relasi ke Role  
	CreatedAt time.Time `gorm:"autoCreateTime"`      // Waktu dibuat  
}  

