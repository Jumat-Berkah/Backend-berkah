package model

import "time"

type Location struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Name        string `gorm:"type:varchar(100);not null" json:"name"`
	Address     string `gorm:"type:text;not null" json:"address"`
	Description string `gorm:"type:text" json:"description"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ActiveToken struct {
	ID        uint      `gorm:"primaryKey"`               // ID unik untuk setiap token
	UserID    uint      `gorm:"not null"`                // ID user yang memiliki token ini (relasi ke tabel User)
	Token     string    `gorm:"unique;not null"`         // Token JWT
	ExpiresAt time.Time `gorm:"not null"`                // Waktu kedaluwarsa token
	CreatedAt time.Time `gorm:"autoCreateTime"`          // Waktu token dibuat
	UpdatedAt time.Time `gorm:"autoUpdateTime"`          // Waktu token terakhir diperbarui
}