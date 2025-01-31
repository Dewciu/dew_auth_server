package models

import (
	"time"

	"github.com/google/uuid"
)

type Consent struct {
	BaseModel
	ClientID  uuid.UUID `gorm:"type:uuid;not null"`
	UserID    uuid.UUID `gorm:"type:uuid;not null"`
	Scopes    string    `gorm:"type:text;not null"`
	GrantedAt time.Time `gorm:"not null"`
	Client    Client    `gorm:"foreignKey:ClientID"`
	User      User      `gorm:"foreignKey:UserID"`
}
