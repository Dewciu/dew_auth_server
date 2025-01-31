package models

import (
	"github.com/google/uuid"
)

// User represents a user in the OAuth system.
type User struct {
	BaseModel
	ID           uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"` // User ID
	Username     string    `gorm:"unique;not null"`
	PasswordHash string    `gorm:"not null"`
	Email        string    `gorm:"unique;not null"`
}
