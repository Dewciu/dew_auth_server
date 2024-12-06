package models

import (
	"time"

	"github.com/google/uuid"
)

// AuthorizationCode represents an issued authorization code.
type AuthorizationCode struct {
	BaseModel
	Code                string    `gorm:"unique;not null"`
	UserID              uuid.UUID `gorm:"type:uuid;not null"`
	ClientID            uuid.UUID `gorm:"type:uuid;not null"`
	RedirectURI         string    `gorm:"not null"`
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time `gorm:"not null"`
	User                User      `gorm:"foreignKey:UserID"`
	Client              Client    `gorm:"foreignKey:ClientID"`
}
