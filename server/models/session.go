package models

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	BaseModel
	ClientID  uuid.UUID `gorm:"type:uuid;not null"`  // Client ID
	UserID    uuid.UUID `gorm:"type:uuid;not null"`  // User ID
	ExpiresAt time.Time `gorm:"not null"`            // Expiration time
	Client    Client    `gorm:"foreignKey:ClientID"` // Relationship to client
	User      User      `gorm:"foreignKey:UserID"`   // Relationship to user
}
