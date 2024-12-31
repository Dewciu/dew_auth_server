package models

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	BaseModel
	ClientID  uuid.UUID `gorm:"type:uuid;not null"`
	UserID    uuid.UUID `gorm:"type:uuid;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	Client    Client    `gorm:"foreignKey:ClientID"`
	User      User      `gorm:"foreignKey:UserID"`
}
