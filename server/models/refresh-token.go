package models

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents an issued refresh token.
type RefreshToken struct {
	BaseModel
	Token         string    `gorm:"unique;not null"`
	UserID        uuid.UUID `gorm:"type:uuid;not null"`
	ClientID      uuid.UUID `gorm:"type:uuid;not null"`
	AccessTokenID uuid.UUID `gorm:"type:uuid;not null"`
	Scope         string
	ExpiresAt     time.Time `gorm:"not null"`
	User          User      `gorm:"foreignKey:UserID"`
	Client        Client    `gorm:"foreignKey:ClientID"`
}
