package models

import (
	"github.com/google/uuid"
)

type Client struct {
	BaseModel
	ID            uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"` // Client ID
	Secret        string    `gorm:"type:varchar(255);not null;unique"`    // Client secret (hashed)
	RedirectURI   string    `gorm:"type:text;not null"`
	GrantTypes    string    `gorm:"type:text"`                         // Comma-separated grant types
	ResponseTypes string    `gorm:"type:text"`                         // Comma-separated response types
	Scopes        string    `gorm:"type:text"`                         // Comma-separated scopes
	ContactEmail  string    `gorm:"type:varchar(255);not null;unique"` // Contact email
	Name          string    `gorm:"type:varchar(255);not null;unique"` // Client name
	Sessions      []Session `gorm:"foreignKey:ClientID"`               // Relationship to sessions
}
