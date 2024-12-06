package models

import (
	"time"

	"github.com/google/uuid"
)

// AccessToken represents an issued access token.
type AccessToken struct {
	BaseModel
	Token     string    `gorm:"unique;not null"`
	UserID    uuid.UUID `gorm:"type:uuid;not null"`
	ClientID  uuid.UUID `gorm:"type:uuid;not null"`
	Scope     string
	ExpiresAt time.Time `gorm:"not null"`
	User      User      `gorm:"foreignKey:UserID"`
	Client    Client    `gorm:"foreignKey:ClientID"`
}
