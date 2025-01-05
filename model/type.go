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