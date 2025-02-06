package model

import "time"

type GoogleUser struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	GoogleID   string    `gorm:"unique;not null" json:"sub"`
	Email      string    `gorm:"unique;not null" json:"email"`
	Name       string    `json:"name"`
	PictureURL string    `gorm:"column:picture_url" json:"picture_url"`
	CreatedAt  time.Time `json:"created_at"`
	LastLogin  time.Time `json:"last_login"`
	RoleID     uint      `json:"role_id"`
	Role       Role      `gorm:"foreignKey:RoleID" json:"role"`
	IsActive   bool      `gorm:"default:true" json:"is_active"`
}

func (GoogleUser) TableName() string {
    return "google_users"
}